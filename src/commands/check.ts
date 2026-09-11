import { loadConfig } from "../config.js";
import { classifyEntry, reconcileWithAudit } from "../check/classify.js";
import { readMetadata, writeMetadata } from "../metadata/store.js";
import { syncOverridesToPackageJson } from "../metadata/sync.js";
import { nowIso } from "../util/time.js";
import {
  createLiveAudit,
  filterFindings,
  findingsToGroups,
  uncoveredFindings,
} from "../audit/client.js";
import { importOverridesFromPackageJson } from "../metadata/import.js";
import { analyzeNpmGraph } from "../graph/npm.js";
import type {
  AuditClient,
  CheckEntry,
  CheckStatus,
  CommandResult,
  MetadataEntry,
  PackageAlertGroup,
} from "../types.js";

export async function runCheck(opts: {
  cwd: string;
  strict?: boolean;
  apply?: boolean;
  yes?: boolean;
  enableAudit?: boolean;
  audit?: AuditClient;
}): Promise<CommandResult> {
  const cwd = opts.cwd;
  const config = loadConfig(cwd);
  const metadata = readMetadata(cwd, config);
  const active = metadata.entries.filter(
    (e) => e.status === "active" || e.status === "pending_verify" || e.status === "verify_failed",
  );
  const classified = active.map((e) => classifyEntry(cwd, e));
  const untracked = untrackedOverrides(cwd, config, metadata);
  classified.push(...untracked);

  const auditEnabled = opts.enableAudit ?? config.audit.enabled;
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
    classified.push(...newGroups.map((group) => entryFromAuditGroup(cwd, group)));
  }

  const counts: Record<string, number> = {};
  for (const c of classified) {
    counts[c.status] = (counts[c.status] ?? 0) + 1;
  }

  const removableCount = classified.filter((c) =>
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
  if (!classified.length) {
    messages.push(
      "Nothing to show: no security-metadata.json entries and no package.json overrides. Run init, analyze/fix, or check --audit.",
    );
  }
  if (auditEnabled) {
    messages.push(
      auditError
        ? `audit failed: ${auditError}`
        : `audit: ${newGroups.length} untracked finding(s) (≥ ${config.audit.minSeverity})`,
    );
  }

  let written: string[] = [];
  if (opts.apply) {
    const removable = classified.filter((c) =>
      ["REMOVABLE", "RESOLVED"].includes(c.status as CheckStatus),
    );
    for (const item of removable) {
      const entry = metadata.entries.find((e) => e.id === item.entry.id);
      if (!entry) continue;
      entry.status = "resolved";
      entry.resolvedAt = nowIso();
      entry.resolution = item.status === "RESOLVED" ? "naturally-resolved" : "root-upgrade-available";
    }
    writeMetadata(cwd, config, metadata);
    syncOverridesToPackageJson(cwd, metadata);
    written = [config.metadataPath, "package.json"];
    messages.push(`Resolved ${removable.length} override(s)`);
  }

  const overdueHigh = classified.some(
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
    writtenFiles: written,
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
      entries: classified,
      groups: newGroups.length ? newGroups : undefined,
    },
  };
}

function untrackedOverrides(
  cwd: string,
  config: import("../types.js").SupplywardenConfig,
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
    .map((entry) => ({
      entry: { ...entry, id: `untracked:${entry.package}` },
      status: "UNTRACKED" as const,
      statuses: ["UNTRACKED" as const],
      suggestedAction: "Override only in package.json — run `supplywarden init`",
      issues: [],
      roots: entry.rootPackages,
      chains: entry.dependencyChains,
    }));
}

function entryFromAuditGroup(cwd: string, group: PackageAlertGroup): CheckEntry {
  const graph = analyzeNpmGraph(cwd, group.package);
  const entry: MetadataEntry = {
    id: `audit:${group.package}`,
    status: "pending_verify",
    package: group.package,
    forcedVersion: group.forcedVersion ?? "?",
    scope: { type: "global" },
    advisories: group.advisories,
    reason: "Untracked finding from package-manager audit",
    strategy: "override",
    rootPackages: graph.roots.map((r) => r.name),
    dependencyChains: graph.chains.map((c) => c.path.join(" → ")),
    packageManager: "npm",
    manifestPath: group.manifestPath,
    createdAt: nowIso(),
    createdBy: "audit",
    reviewBy: nowIso(),
    reviewReason: "New audit finding – run analyze/fix to track as an override",
    needsReview: true,
  };
  const roots = graph.roots.map((r) => r.name);
  const chains = graph.chains.map((c) => c.path.join(" → "));
  return {
    entry,
    status: "NEW",
    statuses: ["NEW"],
    suggestedAction: roots.length
      ? `New (${group.maxSeverity}) via ${roots.join(", ")} — run \`supplywarden why ${group.package}\` then \`supplywarden analyze --audit\``
      : `New (${group.maxSeverity}) — run \`supplywarden why ${group.package}\` then \`supplywarden analyze --audit\``,
    issues: [],
    roots,
    chains,
    installedVersions: graph.versions,
  };
}
