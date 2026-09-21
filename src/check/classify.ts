import { specAtLeast, specFloorSafe, specMinVersion, versionSatisfiesSpec } from "../util/semver-spec.js";
import { firstSafeForcedVersion, stillVulnerable } from "../decision/engine.js";
import { analyzeNpmGraph } from "../graph/npm.js";
import { extractExistingOverrides, readPackageJson } from "../metadata/sync.js";
import { loadConfig } from "../config.js";
import { daysOverdue, isPast } from "../util/time.js";
import type {
  Advisory,
  AuditFinding,
  CheckEntry,
  CheckStatus,
  MetadataEntry,
  RemovableReason,
  ValidationIssue,
} from "../types.js";

function declaredDepRange(cwd: string, manifestPath: string, pkgName: string): string | undefined {
  try {
    const pkg = readPackageJson(cwd, manifestPath);
    const bags = [pkg.dependencies, pkg.devDependencies, pkg.optionalDependencies];
    for (const bag of bags) {
      if (bag && typeof bag === "object" && pkgName in (bag as Record<string, unknown>)) {
        const range = (bag as Record<string, unknown>)[pkgName];
        if (typeof range === "string") return range.replace(/^npm:/, "");
      }
    }
  } catch {
    return undefined;
  }
  return undefined;
}

/** Direct dep and/or override spec already require at least the advisory's patched floor. */
function directDepAlreadyAtPatched(cwd: string, entry: MetadataEntry): boolean {
  const patched = firstSafeForcedVersion(entry.advisories);
  const overrideFloor = specMinVersion(entry.forcedVersion);
  if (patched && overrideFloor && !specAtLeast(entry.forcedVersion, patched)) return false;
  const range = declaredDepRange(cwd, entry.manifestPath, entry.package);
  if (!range) return false;
  if (entry.advisories.length) {
    return specFloorSafe(range, entry.advisories) && specFloorSafe(entry.forcedVersion, entry.advisories);
  }
  return Boolean(overrideFloor && specMinVersion(range) === overrideFloor);
}

function overridePresent(cwd: string, entry: MetadataEntry): boolean {
  try {
    const pkg = readPackageJson(cwd, entry.manifestPath);
    const found = extractExistingOverrides(pkg);
    return found.some(
      (o) => o.package === entry.package && specAtLeast(o.version, entry.forcedVersion),
    );
  } catch {
    return false;
  }
}

/** True when every depender already requires a patched floor — override is leftover, not holding the tree. */
export function parentRangesAlreadySafe(ranges: string[], advisories: Advisory[]): boolean {
  if (!advisories.length || !ranges.length) return false;
  return ranges.every((range) => specFloorSafe(range, advisories));
}

export function classifyEntry(
  cwd: string,
  entry: MetadataEntry,
  now = new Date(),
): CheckEntry {
  const statuses: CheckStatus[] = [];
  const issues: ValidationIssue[] = [];
  const graph = analyzeNpmGraph(cwd, entry.package);
  const roots = graph.roots.map((r) => r.name);
  const chains = graph.chains.map((c) => c.path.join(" → "));
  const threshold = loadConfig(cwd).upgradeRootThreshold;
  let removableReason: RemovableReason | undefined;

  if (entry.status === "pending_verify") {
    statuses.push("PENDING_VERIFY");
  }
  if (entry.status === "verify_failed") {
    statuses.push("VERIFY_FAILED");
  }

  const inPackageJson = overridePresent(cwd, entry);
  if (entry.status === "active" && !inPackageJson && entry.strategy !== "wait") {
    statuses.push("DRIFT");
    issues.push({
      code: "OK",
      message: "package.json override missing or different — run supplywarden sync",
      blocking: false,
    });
  }

  const vulnVersions = graph.versions.filter((v) =>
    entry.advisories.length ? stillVulnerable(v, entry.advisories) : false,
  );
  const onlyForcedInTree =
    graph.versions.length === 1 && versionSatisfiesSpec(graph.versions[0]!, entry.forcedVersion);
  const lockfileSafe =
    vulnVersions.length === 0 && (entry.advisories.length > 0 || onlyForcedInTree);
  const alreadyPatched = directDepAlreadyAtPatched(cwd, entry);
  const parentsSafe = parentRangesAlreadySafe(graph.dependerRanges, entry.advisories);
  const weakOverride =
    entry.advisories.length > 0 && !specFloorSafe(entry.forcedVersion, entry.advisories);

  if (entry.status === "active" && !graph.inTree) {
    statuses.push("RESOLVED");
    statuses.push("REMOVABLE");
    removableReason = "not-in-tree";
  } else if (entry.status === "active" && alreadyPatched && lockfileSafe) {
    statuses.push("RESOLVED");
    statuses.push("REMOVABLE");
    removableReason = "already-at-patched";
  } else if (entry.status === "active" && graph.inTree && vulnVersions.length === 0 && parentsSafe) {
    statuses.push("RESOLVED");
    statuses.push("REMOVABLE");
    removableReason = "no-vulnerable-version";
  }

  // onlyForcedInTree with many roots = the override is holding the tree, not leftover.
  // Few roots = prefer upgrading those packages; still not verify --apply.

  if (entry.status === "active" && isPast(entry.reviewBy, now)) {
    statuses.push("OVERDUE");
  }

  if (!statuses.length) statuses.push("OK");

  const primary = pickPrimary(statuses);
  return {
    entry,
    status: primary,
    statuses,
    suggestedAction: suggest(primary, entry, roots, now, removableReason, {
      threshold,
      onlyForcedInTree,
      installed: graph.versions[0],
      weak: weakOverride && !statuses.includes("REMOVABLE") && !statuses.includes("RESOLVED"),
      forced: entry.forcedVersion,
      need: firstSafeForcedVersion(entry.advisories),
    }),
    issues,
    removableReason,
    roots,
    chains,
    installedVersions: graph.versions,
    dependerRanges: graph.dependerRanges,
    dependencyKind: graph.dependencyKind,
    weakOverride: weakOverride && !statuses.includes("REMOVABLE") && !statuses.includes("RESOLVED"),
  };
}

export function reconcileWithAudit(classified: CheckEntry[], findings: AuditFinding[]): CheckEntry[] {
  const findingPkgs = new Set(findings.map((f) => f.package));
  return classified.map((item) => {
    if (item.status === "NEW" || item.status === "UNTRACKED") return item;
    if (item.entry.status !== "active") return item;
    if (item.statuses.includes("DRIFT")) return item;
    if (findingPkgs.has(item.entry.package)) return item;

    const parentsSafe = parentRangesAlreadySafe(item.dependerRanges ?? [], item.entry.advisories);
    const lockfileSupports =
      item.statuses.includes("RESOLVED") ||
      item.statuses.includes("REMOVABLE") ||
      item.removableReason === "not-in-tree" ||
      item.removableReason === "no-vulnerable-version" ||
      item.removableReason === "already-at-patched" ||
      parentsSafe ||
      (item.installedVersions ?? []).length === 0;

    if (!lockfileSupports) {
      return {
        ...item,
        auditClear: true,
        suggestedAction: auditClearHint(item),
      };
    }

    const statuses = new Set(item.statuses);
    statuses.delete("OK");
    statuses.add("RESOLVED");
    statuses.add("REMOVABLE");
    const list = [...statuses];
    const status = pickPrimary(list);
    return {
      ...item,
      status,
      statuses: list,
      removableReason: item.removableReason ?? "audit-clear",
      suggestedAction: suggest(status, item.entry, item.roots ?? [], new Date(), item.removableReason ?? "audit-clear"),
    };
  });
}

export function isDropCandidate(entry: CheckEntry): boolean {
  return entry.statuses.includes("REMOVABLE") || entry.statuses.includes("RESOLVED");
}

export function pickPrimary(statuses: CheckStatus[]): CheckStatus {
  const order: CheckStatus[] = [
    "VERIFY_FAILED",
    "NEW",
    "UNTRACKED",
    "DRIFT",
    "RESOLVED",
    "REMOVABLE",
    "OVERDUE",
    "STALE",
    "PENDING_VERIFY",
    "OK",
  ];
  return order.find((s) => statuses.includes(s)) ?? "OK";
}

export function removableReasonLabel(reason?: RemovableReason): string {
  switch (reason) {
    case "not-in-tree":
      return "No longer in the lockfile";
    case "no-vulnerable-version":
      return "No vulnerable version left in the tree";
    case "already-at-patched":
      return "package.json already depends on the patched version — override is leftover";
    case "root-upgrade-candidate":
      return "Lockfile shows only the forced version because the override is holding it — not leftover";
    case "audit-clear":
      return "Live audit no longer lists this package";
    default:
      return "—";
  }
}

function suggest(
  status: CheckStatus,
  entry: MetadataEntry,
  roots: string[],
  now: Date,
  reason?: RemovableReason,
  hold?: {
    threshold: number;
    onlyForcedInTree: boolean;
    installed?: string;
    weak?: boolean;
    forced?: string;
    need?: string;
  },
): string {
  const pkg = entry.package;
  switch (status) {
    case "REMOVABLE":
      if (reason === "already-at-patched") {
        return `package.json already depends on patched ${pkg} — leftover override, run \`supplywarden verify ${pkg} --apply\``;
      }
      return `Override resolved naturally — run \`supplywarden verify ${pkg} --apply\``;
    case "RESOLVED":
      if (reason === "already-at-patched") {
        return `package.json already depends on patched ${pkg} — leftover override, run \`supplywarden verify ${pkg} --apply\``;
      }
      return `No longer in the lockfile / no longer vulnerable — run \`supplywarden verify ${pkg} --apply\``;
    case "OVERDUE":
      if (hold?.weak) return holdingOverrideAction(pkg, roots, hold);
      if (entry.strategy === "wait") {
        return `Wait expired — decide upgrade or override. Run \`supplywarden why ${pkg}\` then \`supplywarden fix --apply\``;
      }
      return `Review ${daysOverdue(entry.reviewBy, now)}d overdue — run \`supplywarden why ${pkg}\``;
    case "DRIFT":
      return "package.json drifted — run `supplywarden sync`";
    case "VERIFY_FAILED":
      return `Last verify/apply did not stick — retry with \`supplywarden verify ${pkg}\``;
    case "PENDING_VERIFY":
      return `Override is in package.json but the lockfile is still old — run npm install, then \`supplywarden check\``;
    case "NEW":
      return `Untracked audit finding — run \`supplywarden why ${pkg}\` then \`supplywarden fix --apply\``;
    case "UNTRACKED":
      return suggestUntracked(undefined, pkg, roots);
    case "STALE":
      return `Override is stale — run \`supplywarden why ${pkg}\``;
    default:
      if (entry.strategy === "wait") {
        return `Waiting — no override this cycle. Re-open with \`supplywarden why ${pkg}\` or wait until reviewBy`;
      }
      return holdingOverrideAction(pkg, roots, hold);
  }
}

function holdingOverrideAction(
  pkg: string,
  roots: string[],
  hold?: {
    threshold: number;
    onlyForcedInTree: boolean;
    installed?: string;
    weak?: boolean;
    forced?: string;
    need?: string;
  },
): string {
  if (hold?.weak) {
    const need = hold.need ?? "a patched version";
    const installed = hold.installed ? ` Lockfile is ${hold.installed}.` : "";
    return `Override ${hold.forced ?? "spec"} still allows vulnerable versions (need ${need}).${installed} Keeping it is a no-op — run \`supplywarden fix --apply\`, not \`verify --apply\``;
  }
  const n = roots.length;
  const threshold = hold?.threshold ?? 3;
  if (hold?.onlyForcedInTree && n > threshold) {
    const ver = hold.installed ? `@${hold.installed}` : "";
    return `Installed ${pkg}${ver} is held for ${n} roots (threshold ${threshold} → not a root upgrade). Parent specs may still allow older versions — a hint, not a block. Run \`supplywarden verify ${pkg}\` to test dropping it.`;
  }
  if (hold?.onlyForcedInTree && n > 0 && n <= threshold) {
    return `Override may still be holding the tree. ${n} root(s) ≤ threshold ${threshold}: prefer upgrading ${roots.join(", ")}. Or run \`supplywarden verify ${pkg}\` to test dropping the override.`;
  }
  return roots.length
    ? `Override may still be holding the tree — pulled by ${roots.join(", ")}. Run \`supplywarden verify ${pkg}\` to test dropping it.`
    : `Override may still be holding the tree — run \`supplywarden verify ${pkg}\` to test dropping it.`;
}

function auditClearHint(item: CheckEntry): string {
  const pkg = item.entry.package;
  const installed = (item.installedVersions ?? []).join(", ") || "unknown";
  const ranges = item.dependerRanges ?? [];
  const rangeNote = ranges.length
    ? ` Parents still declare ${ranges.join(", ")} (lockfile specs, not installed). That is a hint — not a block.`
    : "";
  return `Live npm audit does not list ${pkg} (installed ${installed}).${rangeNote} Run \`supplywarden verify ${pkg}\` to test dropping the override.`;
}

function suggestUntracked(reason: RemovableReason | undefined, pkg: string, roots: string[]): string {
  if (reason === "not-in-tree") {
    return `package.json override not used (not in lockfile, no roots) — run \`supplywarden init\` then \`supplywarden verify ${pkg} --apply\``;
  }
  if (reason === "already-at-patched") {
    return `package.json already depends on patched ${pkg} — leftover override, run \`supplywarden init\` then \`supplywarden verify ${pkg} --apply\``;
  }
  if (reason === "root-upgrade-candidate") {
    return `Untracked override only forced version, roots ${roots.join(", ")} — run \`supplywarden init\` then \`supplywarden why ${pkg}\` (not verify --apply)`;
  }
  if (roots.length) {
    return `Untracked override still pulled by ${roots.join(", ")} — run \`supplywarden init\``;
  }
  return "Override only in package.json — run `supplywarden init`";
}

export function classifyUntrackedOverride(cwd: string, entry: MetadataEntry): CheckEntry {
  const graph = analyzeNpmGraph(cwd, entry.package);
  const roots = graph.roots.map((r) => r.name);
  const chains = graph.chains.map((c) => c.path.join(" → "));
  const statuses: CheckStatus[] = ["UNTRACKED"];
  let removableReason: RemovableReason | undefined;

  if (!graph.inTree) {
    statuses.push("REMOVABLE");
    removableReason = "not-in-tree";
  } else if (
    directDepAlreadyAtPatched(cwd, entry) &&
    (entry.advisories.length
      ? !graph.versions.some((v) => stillVulnerable(v, entry.advisories))
      : graph.versions.length === 1 && versionSatisfiesSpec(graph.versions[0]!, entry.forcedVersion))
  ) {
    statuses.push("REMOVABLE");
    removableReason = "already-at-patched";
  } else if (
    entry.advisories.length > 0 &&
    parentRangesAlreadySafe(graph.dependerRanges, entry.advisories)
  ) {
    statuses.push("REMOVABLE");
    removableReason = "no-vulnerable-version";
  }

  return {
    entry: {
      ...entry,
      id: entry.id.startsWith("untracked:") ? entry.id : `untracked:${entry.package}`,
    },
    status: pickPrimary(statuses),
    statuses,
    suggestedAction: suggestUntracked(removableReason, entry.package, roots),
    issues: [],
    removableReason,
    roots,
    chains,
    installedVersions: graph.versions,
    dependerRanges: graph.dependerRanges,
    dependencyKind: graph.dependencyKind,
  };
}

export function sortCheckEntries(entries: CheckEntry[]): CheckEntry[] {
  const rank = (e: CheckEntry): number => {
    if (e.status === "NEW" || e.statuses.includes("NEW")) return 0;
    if (e.status === "VERIFY_FAILED" || e.statuses.includes("VERIFY_FAILED")) return 1;
    if (e.status === "OVERDUE" || e.statuses.includes("OVERDUE")) return 2;
    if (e.status === "DRIFT" || e.statuses.includes("DRIFT")) return 3;
    if (e.statuses.includes("REMOVABLE") || e.statuses.includes("RESOLVED")) return 4;
    if (e.status === "UNTRACKED" || e.statuses.includes("UNTRACKED")) return 5;
    if (e.status === "PENDING_VERIFY" || e.statuses.includes("PENDING_VERIFY")) return 6;
    return 7;
  };
  return [...entries].sort((a, b) => {
    const d = rank(a) - rank(b);
    if (d !== 0) return d;
    return a.entry.package.localeCompare(b.entry.package);
  });
}
