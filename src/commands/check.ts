import { loadConfig } from "../config.js";
import {
  classifyEntry,
  classifyUntrackedOverride,
  isDropCandidate,
  reconcileWithAudit,
  sortCheckEntries,
} from "../check/classify.js";
import { decide, formatUpgradeTarget, resolveUpgradeDecision } from "../decision/engine.js";
import { specFloorSafe } from "../util/semver-spec.js";
import { readMetadata } from "../metadata/store.js";
import { nowIso } from "../util/time.js";
import {
  createLiveAudit,
  filterFindings,
  findingsToGroups,
  uncoveredFindings,
} from "../audit/client.js";
import { importOverridesFromPackageJson } from "../metadata/import.js";
import { analyzeNpmGraph, dependencyKindLabel, mergeDependencyKind, resolvePackageManager } from "../graph/npm.js";
import { createLiveRegistry } from "../registry/verify.js";
import type {
  AuditClient,
  CheckEntry,
  CommandResult,
  Decision,
  DependencyKind,
  MetadataEntry,
  PackageAlertGroup,
  RegistryClient,
  SupplywardenConfig,
} from "../types.js";

export async function runCheck(opts: {
  cwd: string;
  strict?: boolean;
  enableAudit?: boolean;
  audit?: AuditClient;
  registry?: RegistryClient;
}): Promise<CommandResult> {
  const cwd = opts.cwd;
  const config = loadConfig(cwd);
  const metadata = readMetadata(cwd, config);
  const active = metadata.entries.filter(
    (e) => e.status === "active" || e.status === "pending_verify" || e.status === "verify_failed",
  );
  const classified = active.map((e) => classifyEntry(cwd, e));
  const untracked = listUntrackedOverrides(cwd, config, metadata);
  classified.push(...untracked);

  const auditEnabled = opts.enableAudit !== false;
  let auditError: string | undefined;
  const newGroups: PackageAlertGroup[] = [];

  if (auditEnabled) {
    const client = opts.audit ?? createLiveAudit();
    const result = await client.audit(cwd);
    auditError = result.error;
    const filtered = filterFindings(result.vulnerabilities, config.audit.minSeverity);
    if (!auditError) {
      const reconciled = reconcileWithAudit(classified, filtered);
      classified.splice(0, classified.length, ...reconciled);
    }
    const uncovered = uncoveredFindings(filtered, metadata.entries);
    newGroups.push(...findingsToGroups(uncovered));
    const registry = opts.registry ?? (opts.audit ? undefined : createLiveRegistry());
    classified.push(
      ...(await Promise.all(newGroups.map((group) => entryFromAuditGroup(cwd, group, config, registry)))),
    );
  }

  const sorted = sortCheckEntries(classified);

  const counts: Record<string, number> = {};
  for (const c of sorted) {
    counts[c.status] = (counts[c.status] ?? 0) + 1;
  }

  const removableCount = sorted.filter((c) =>
    c.statuses.includes("REMOVABLE") || c.statuses.includes("RESOLVED"),
  ).length;
  const messages = [
    `supplywarden check – ${active.length} active overrides`,
    `Summary: ${Object.entries(counts)
      .map(([k, v]) => `${v} ${k.toLowerCase()}`)
      .join(" · ") || "none"}`,
  ];
  if (untracked.length) {
    messages.push(
      `${untracked.length} override(s) in package.json are untracked — run supplywarden init`,
    );
  }
  if (!sorted.length) {
    messages.push(
      "Nothing to show: no security-metadata.json entries and no package.json overrides. Run init or analyze/fix.",
    );
  }
  if (auditEnabled) {
    messages.push(
      auditError
        ? `audit failed: ${auditError}`
        : `audit: ${newGroups.length} untracked finding(s) (≥ ${config.audit.minSeverity})`,
    );
  }

  const overdueHigh = sorted.some(
    (c) =>
      c.statuses.includes("OVERDUE") &&
      c.entry.advisories.some((a) => a.severity === "high" || a.severity === "critical"),
  );
  const hasNew = (counts.NEW ?? 0) > 0;
  const hasUntracked = (counts.UNTRACKED ?? 0) > 0;
  const exitCode =
    opts.strict &&
    (overdueHigh ||
      (counts.DRIFT ?? 0) > 0 ||
      (counts.VERIFY_FAILED ?? 0) > 0 ||
      hasNew ||
      hasUntracked ||
      Boolean(auditError))
      ? 1
      : 0;

  if (opts.strict && exitCode === 1) {
    messages.push(
      "strict: failing due to overdue high/critical, drift, verify_failed, new audit findings, or untracked overrides",
    );
  }

  return {
    exitCode,
    messages,
    report: {
      title: `supplywarden check – ${active.length} active overrides`,
      generatedAt: nowIso(),
      cwd,
      summary: {
        active: active.length,
        untracked: untracked.length,
        removable: removableCount,
        ...counts,
        ...(auditEnabled ? { auditNew: newGroups.length } : {}),
      },
      entries: sorted,
      groups: newGroups.length ? newGroups : undefined,
    },
  };
}

export function listTrackedAndUntrackedOverrides(
  cwd: string,
  config: SupplywardenConfig,
): CheckEntry[] {
  const metadata = readMetadata(cwd, config);
  const tracked = metadata.entries
    .filter((e) => e.status === "active" || e.status === "pending_verify" || e.status === "verify_failed")
    .map((e) => classifyEntry(cwd, e));
  const untracked = listUntrackedOverrides(cwd, config, metadata);
  return [...tracked, ...untracked];
}

export function listDropCandidates(cwd: string, config: SupplywardenConfig): CheckEntry[] {
  return listTrackedAndUntrackedOverrides(cwd, config).filter(isDropCandidate);
}

export function listOverridesToProbe(
  cwd: string,
  config: SupplywardenConfig,
  pkg?: string,
): CheckEntry[] {
  const all = listTrackedAndUntrackedOverrides(cwd, config);
  if (pkg) {
    return all.filter((e) => e.entry.package === pkg);
  }
  return all.filter(isDropCandidate);
}

export function listUntrackedOverrides(
  cwd: string,
  config: SupplywardenConfig,
  metadata: import("../types.js").SecurityMetadata,
): CheckEntry[] {
  const imported = importOverridesFromPackageJson(cwd, config, (pkg) => analyzeNpmGraph(cwd, pkg));
  const tracked = new Set(
    metadata.entries
      .filter((e) => e.status !== "resolved" && e.status !== "superseded")
      .map((e) => `${e.package}::${e.forcedVersion}`),
  );
  return imported
    .filter((e) => !tracked.has(`${e.package}::${e.forcedVersion}`))
    .map((entry) => classifyUntrackedOverride(cwd, entry));
}

function newFindingAction(
  group: PackageAlertGroup,
  decision: Decision,
  roots: string[],
  kind?: DependencyKind,
): string {
  const kindTag = dependencyKindLabel(kind);
  const sev = group.maxSeverity.toUpperCase() + (kindTag ? ` (${kindTag})` : "");
  if (decision.strategy === "upgrade") {
    const targets = (decision.upgradeTargets ?? [])
      .map((t) => formatUpgradeTarget(t))
      .join(", ");
    return `New ${sev}: UPGRADE ${targets || roots.join(", ") || group.package} — run \`supplywarden fix --apply\``;
  }
  const ver = decision.forcedVersion ?? group.forcedVersion;
  if (!ver || !specFloorSafe(ver, group.advisories)) {
    return `New ${sev}: ${group.package} has no safe override version — inspect with \`supplywarden why ${group.package}\` (not \`fix --apply\`)`;
  }
  const rootPart = roots.length ? ` (roots: ${roots.join(", ")})` : "";
  return `New ${sev}: OVERRIDE ${group.package}@${ver}${rootPart} — run \`supplywarden fix --apply\``;
}

async function entryFromAuditGroup(
  cwd: string,
  group: PackageAlertGroup,
  config: SupplywardenConfig,
  registry?: RegistryClient,
): Promise<CheckEntry> {
  const graph = analyzeNpmGraph(cwd, group.package);
  const decision = await resolveUpgradeDecision(decide({ graph, advisories: group.advisories, config }), {
    latestVersion: registry?.latestVersion?.bind(registry),
    getLatestMatching: registry?.getLatestMatching?.bind(registry),
  });
  const roots = graph.roots.map((r) => r.name);
  const chains = graph.chains.map((c) => c.path.join(" → "));
  const kind = mergeDependencyKind(group.dependencyKind, graph.dependencyKind);
  const entry: MetadataEntry = {
    id: `audit:${group.package}`,
    status: "pending_verify",
    package: group.package,
    forcedVersion: decision.forcedVersion ?? group.forcedVersion ?? "?",
    scope: decision.scope,
    advisories: group.advisories,
    reason: "Untracked finding from package-manager audit",
    strategy: decision.strategy,
    rootPackages: roots,
    dependencyChains: chains,
    packageManager: resolvePackageManager(cwd),
    manifestPath: group.manifestPath,
    createdAt: nowIso(),
    createdBy: "audit",
    reviewBy: nowIso(),
    reviewReason: "New audit finding – run fix --apply to track",
    needsReview: true,
  };
  return {
    entry,
    status: "NEW",
    statuses: ["NEW"],
    suggestedAction: newFindingAction(group, decision, roots, kind),
    issues: [],
    roots,
    chains,
    installedVersions: graph.versions,
    decision,
    dependencyKind: kind,
  };
}
