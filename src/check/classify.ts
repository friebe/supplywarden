import { stillVulnerable } from "../decision/engine.js";
import { analyzeNpmGraph } from "../graph/npm.js";
import { extractExistingOverrides, readPackageJson } from "../metadata/sync.js";
import { daysOverdue, isPast } from "../util/time.js";
import type {
  AuditFinding,
  CheckEntry,
  CheckStatus,
  MetadataEntry,
  RemovableReason,
  ValidationIssue,
} from "../types.js";

function overridePresent(cwd: string, entry: MetadataEntry): boolean {
  try {
    const pkg = readPackageJson(cwd, entry.manifestPath);
    const found = extractExistingOverrides(pkg);
    return found.some(
      (o) =>
        o.package === entry.package &&
        o.version === entry.forcedVersion,
    );
  } catch {
    return false;
  }
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
  let removableReason: RemovableReason | undefined;

  if (entry.status === "pending_verify") {
    statuses.push("PENDING_VERIFY");
  }
  if (entry.status === "verify_failed") {
    statuses.push("VERIFY_FAILED");
  }

  const inPackageJson = overridePresent(cwd, entry);
  if (entry.status === "active" && !inPackageJson) {
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

  if (entry.status === "active" && graph.inTree && entry.advisories.length === 0) {
    if (graph.versions.length === 1 && graph.versions[0] === entry.forcedVersion) {
      statuses.push("REMOVABLE");
      removableReason = "root-upgrade-candidate";
    }
  } else if (entry.status === "active" && !graph.inTree && entry.advisories.length > 0) {
    statuses.push("RESOLVED");
    statuses.push("REMOVABLE");
    removableReason = "not-in-tree";
  } else if (entry.status === "active" && graph.inTree && vulnVersions.length === 0 && entry.advisories.length > 0) {
    statuses.push("RESOLVED");
    statuses.push("REMOVABLE");
    removableReason = "no-vulnerable-version";
  } else if (
    entry.status === "active" &&
    graph.inTree &&
    graph.versions.length === 1 &&
    graph.versions[0] === entry.forcedVersion &&
    (entry.advisories.length === 0 || !stillVulnerable(entry.forcedVersion, entry.advisories))
  ) {
    const rootsCanTakeIt = graph.roots.length > 0 && graph.roots.length <= 3;
    if (rootsCanTakeIt) {
      statuses.push("REMOVABLE");
      removableReason = "root-upgrade-candidate";
    }
  }

  if (entry.status === "active" && isPast(entry.reviewBy, now)) {
    statuses.push("OVERDUE");
  }

  if (!statuses.length) statuses.push("OK");

  const primary = pickPrimary(statuses);
  return {
    entry,
    status: primary,
    statuses,
    suggestedAction: suggest(primary, entry, roots, now),
    issues,
    removableReason,
    roots,
    chains,
    installedVersions: graph.versions,
  };
}

export function reconcileWithAudit(classified: CheckEntry[], findings: AuditFinding[]): CheckEntry[] {
  const findingPkgs = new Set(findings.map((f) => f.package));
  return classified.map((item) => {
    if (item.status === "NEW" || item.status === "UNTRACKED") return item;
    if (item.entry.status !== "active") return item;
    if (item.statuses.includes("DRIFT")) return item;
    if (findingPkgs.has(item.entry.package)) return item;

    const lockfileSupports =
      item.statuses.includes("RESOLVED") ||
      item.statuses.includes("REMOVABLE") ||
      item.removableReason === "not-in-tree" ||
      item.removableReason === "no-vulnerable-version" ||
      (item.entry.advisories.length > 0 &&
        (item.installedVersions ?? []).every((v) => !stillVulnerable(v, item.entry.advisories))) ||
      (item.installedVersions ?? []).length === 0;

    if (!lockfileSupports) return item;

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
      suggestedAction: suggest(status, item.entry, item.roots ?? [], new Date()),
    };
  });
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
    case "root-upgrade-candidate":
      return "Only the forced version is in the tree — consider a root upgrade";
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
): string {
  const pkg = entry.package;
  switch (status) {
    case "REMOVABLE":
      return roots.length
        ? `Consider a root upgrade (${roots.join(", ")}) — run \`supplywarden why ${pkg}\` then \`supplywarden verify --apply\``
        : `Override resolved naturally — run \`supplywarden verify --apply\``;
    case "RESOLVED":
      return `No longer in the lockfile / no longer vulnerable — run \`supplywarden verify --apply\``;
    case "OVERDUE":
      return `Review ${daysOverdue(entry.reviewBy, now)}d overdue — run \`supplywarden why ${pkg}\``;
    case "DRIFT":
      return "package.json drifted — run `supplywarden sync`";
    case "VERIFY_FAILED":
      return `Last apply failed — run \`supplywarden why ${pkg}\` then \`supplywarden verify\``;
    case "PENDING_VERIFY":
      return `Pending verify — run \`supplywarden verify\``;
    case "NEW":
      return `Untracked audit finding — run \`supplywarden why ${pkg}\` then \`supplywarden fix --apply\``;
    case "UNTRACKED":
      return suggestUntracked(undefined, pkg, roots);
    case "STALE":
      return `Override is stale — run \`supplywarden why ${pkg}\``;
    default:
      return roots.length
        ? `Override still required — pulled by ${roots.join(", ")}. Run \`supplywarden why ${pkg}\``
        : `Override still required — run \`supplywarden why ${pkg}\``;
  }
}

function suggestUntracked(reason: RemovableReason | undefined, pkg: string, roots: string[]): string {
  if (reason === "not-in-tree") {
    return "package.json override not used (not in lockfile, no roots) — run `supplywarden init` then `supplywarden verify --apply`";
  }
  if (reason === "root-upgrade-candidate") {
    return `Untracked override only forced version, roots ${roots.join(", ")} — run \`supplywarden init\` then \`supplywarden verify --apply\``;
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
    graph.versions.length === 1 &&
    graph.versions[0] === entry.forcedVersion &&
    roots.length > 0 &&
    roots.length <= 3
  ) {
    statuses.push("REMOVABLE");
    removableReason = "root-upgrade-candidate";
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
