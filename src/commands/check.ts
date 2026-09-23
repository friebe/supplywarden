import { actorName, loadConfig } from "../config.js";
import {
  classifyEntry,
  classifyUntrackedOverride,
  isDropCandidate,
  pickPrimary,
  reconcileWithAudit,
  sortCheckEntries,
} from "../check/classify.js";
import { breakingPinNote, breakingUpgradeNote, decide, formatUpgradeTarget, formatUpgradeTargets, lookupFromRegistry, resolveUpgradeDecision } from "../decision/engine.js";
import { specFloorSafe } from "../util/semver-spec.js";
import { newEntryId, readMetadata, writeMetadata } from "../metadata/store.js";
import { addDaysIso, nowIso } from "../util/time.js";
import {
  createLiveAudit,
  filterFindings,
  findingsToGroups,
  uncoveredFindings,
} from "../audit/client.js";
import { importOverridesFromPackageJson } from "../metadata/import.js";
import { alertsFromInput, groupAlerts, loadAlertFile } from "../alerts/dependabot.js";
import { analyzeNpmGraph, dependencyKindLabel, mergeDependencyKind, resolvePackageManager } from "../graph/npm.js";
import { createLiveRegistry } from "../registry/verify.js";
import { rootUpgradeCommands } from "../fix/upgrade-command.js";
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
  /** Dependabot JSON — NEW findings without live `npm audit` (kitchen-sink fixture). */
  alertPath?: string;
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

  if (opts.alertPath) {
    const raw = loadAlertFile(opts.alertPath);
    const known = new Set([
      ...metadata.entries
        .filter((e) => e.status !== "resolved" && e.status !== "superseded")
        .map((e) => e.package),
      ...untracked.map((e) => e.entry.package),
    ]);
    newGroups.push(...groupAlerts(alertsFromInput(raw)).filter((g) => !known.has(g.package)));
    const registry = opts.registry ?? createLiveRegistry(cwd);
    classified.push(
      ...(await Promise.all(newGroups.map((group) => entryFromAuditGroup(cwd, group, config, registry)))),
    );
  } else if (auditEnabled) {
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
    const registry = opts.registry ?? (opts.audit ? undefined : createLiveRegistry(cwd));
    classified.push(
      ...(await Promise.all(newGroups.map((group) => entryFromAuditGroup(cwd, group, config, registry)))),
    );
  }

  const registryForWait = opts.registry ?? createLiveRegistry(cwd);
  const waitNotes = await refreshWaitEntries(cwd, config, classified, registryForWait);
  const promoted = await promoteDeferredUpgrades(cwd, config, classified, registryForWait);
  const seen = recordSeenFindings(metadata, classified, config);
  if (waitNotes.wrote || promoted.wrote || seen.wrote) {
    writeMetadata(cwd, config, metadata);
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
  for (const entry of sorted.filter((c) => c.status === "NEW" || c.statuses.includes("NEW"))) {
    messages.push(formatNewFindingMessage(entry));
  }
  for (const note of waitNotes.messages) messages.push(note);
  for (const note of promoted.messages) messages.push(note);
  if (seen.count) {
    messages.push(
      `Recorded ${seen.count} finding(s) as seen. The next check lists them as deferred, not NEW, until reviewBy.`,
    );
  }
  if (!sorted.length) {
    messages.push(
      "Nothing to show: no security-metadata.json entries and no package.json overrides. Run init or analyze/fix.",
    );
  }
  if (opts.alertPath) {
    messages.push(`alerts: ${newGroups.length} untracked finding(s) from ${opts.alertPath}`);
  } else if (auditEnabled) {
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
    writtenFiles: waitNotes.wrote || promoted.wrote || seen.wrote ? [config.metadataPath] : undefined,
    report: {
      title: `supplywarden check – ${active.length} active overrides`,
      generatedAt: nowIso(),
      cwd,
      summary: {
        active: active.length,
        untracked: untracked.length,
        removable: removableCount,
        ...counts,
        ...(opts.alertPath || auditEnabled ? { auditNew: newGroups.length } : {}),
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

/** Saved WAIT rows are re-decided every check: proven upgrade, override, or another wait cycle. */
async function refreshWaitEntries(
  cwd: string,
  config: SupplywardenConfig,
  classified: CheckEntry[],
  registry: RegistryClient,
): Promise<{ wrote: boolean; messages: string[] }> {
  const messages: string[] = [];
  let wrote = false;
  for (const item of classified) {
    if (item.entry.strategy !== "wait") continue;
    if (item.entry.status !== "active") continue;
    if (item.statuses.includes("REMOVABLE") || item.statuses.includes("RESOLVED")) continue;

    const graph = analyzeNpmGraph(cwd, item.entry.package);
    const kind = mergeDependencyKind(undefined, graph.dependencyKind);
    const decision = await resolveUpgradeDecision(
      decide({
        graph: { ...graph, dependencyKind: kind },
        advisories: item.entry.advisories,
        config,
      }),
      lookupFromRegistry(registry),
      {
        vulnPackage: item.entry.package,
        advisories: item.entry.advisories,
        chains: graph.chains,
        dependencyKind: kind,
      },
    );
    const outcome = waitRecheckOutcome(decision);
    if (outcome === "unknown") {
      messages.push(
        `WAIT ${item.entry.package}: registry recheck inconclusive — still waiting`,
      );
      continue;
    }

    wrote = true;
    if (outcome === "wait") {
      item.entry.reviewBy = addDaysIso(config.defaultReviewDays);
      item.entry.reviewReason = "Wait — rechecked, no proven root upgrade yet";
      const statuses = item.statuses.filter((s) => s !== "OVERDUE");
      if (!statuses.length) statuses.push("OK");
      item.statuses = statuses;
      item.status = pickPrimary(statuses);
      item.suggestedAction = `Still waiting — no proven root upgrade. Next review is reviewBy.`;
      messages.push(`WAIT ${item.entry.package}: still no proven root upgrade`);
      continue;
    }

    item.entry.strategy = decision.strategy;
    item.entry.reason = decision.reason;
    item.entry.reviewReason =
      decision.strategy === "upgrade"
        ? "Root upgrade now closes the advisory"
        : "Override now required";
    item.decision = decision;
    const pm = resolvePackageManager(cwd);
    const displays =
      decision.strategy === "upgrade"
        ? rootUpgradeCommands(pm, decision.upgradeTargets ?? []).map((c) => c.display)
        : [];
    item.upgradeCommand = displays[0];
    item.upgradeCommands = displays.length ? displays : undefined;
    const bump = formatUpgradeTargets(decision);
    item.suggestedAction =
      decision.strategy === "upgrade"
        ? `WAIT recheck: UPGRADE ${bump} — run ${displays.map((c) => `\`${c}\``).join(" then ")}`
        : `WAIT recheck: OVERRIDE ${item.entry.package}@${decision.forcedVersion ?? item.entry.forcedVersion} — run \`supplywarden fix --apply\``;
    messages.push(
      decision.strategy === "upgrade"
        ? `WAIT ${item.entry.package}: now UPGRADE ${bump}${displays.length ? ` — ${displays.join(" then ")}` : ""}`
        : `WAIT ${item.entry.package}: now OVERRIDE ${item.entry.package}@${decision.forcedVersion ?? item.entry.forcedVersion}`,
    );
  }
  return { wrote, messages };
}

function waitRecheckOutcome(decision: Decision): "upgrade" | "override" | "wait" | "unknown" {
  if (decision.strategy === "wait") return "wait";
  if (decision.strategy === "override") return "override";
  const targets = decision.upgradeTargets ?? [];
  if (targets.length > 0 && targets.every((t) => Boolean(t.to))) return "upgrade";
  return "unknown";
}

/** First sighting stays NEW in this report and is stored so the next check is not NEW again. */
function recordSeenFindings(
  metadata: import("../types.js").SecurityMetadata,
  classified: CheckEntry[],
  config: SupplywardenConfig,
): { wrote: boolean; count: number } {
  let count = 0;
  for (const item of classified) {
    if (!item.statuses.includes("NEW")) continue;
    const already = metadata.entries.some(
      (e) =>
        e.package === item.entry.package &&
        e.status !== "resolved" &&
        e.status !== "superseded",
    );
    if (already) continue;
    metadata.entries.push({
      ...item.entry,
      id: newEntryId(),
      status: "active",
      strategy: "defer",
      reason: deferReason(item),
      createdBy: actorName(),
      reviewBy: addDaysIso(config.defaultReviewDays),
      reviewReason: "Seen — not applied this cycle",
      needsReview: true,
    });
    count += 1;
  }
  return { wrote: count > 0, count };
}

function deferReason(entry: CheckEntry): string {
  const installed = entry.installedVersions?.join(", ") || "?";
  const pkg = entry.entry.package;
  const tail = "Not applied this cycle. The next check keeps this out of NEW until reviewBy.";
  if (entry.decision?.strategy === "upgrade") {
    const breaking = breakingUpgradeNote(entry.decision);
    const bump = formatUpgradeTargets(entry.decision) || (entry.roots ?? []).join(", ") || pkg;
    const cmds = (entry.upgradeCommands ?? (entry.upgradeCommand ? [entry.upgradeCommand] : [])).join(" then ");
    if (breaking) {
      return `Seen, not applied (lockfile ${installed}). ${breaking} ${tail}`;
    }
    return cmds
      ? `Seen, not applied (lockfile ${installed}). Suggested ${bump} — ${cmds}. ${tail}`
      : `Seen, not applied (lockfile ${installed}). Suggested ${bump}. ${tail}`;
  }
  if (entry.decision?.strategy === "wait") {
    return `Seen, not applied (lockfile ${installed}). No override or root upgrade this cycle. ${tail}`;
  }
  const pin = breakingPinNote(pkg, entry.installedVersions ?? [], entry.entry.forcedVersion);
  const override = `Suggested override ${pkg}@${entry.entry.forcedVersion}.`;
  return pin
    ? `Seen, not applied (lockfile ${installed}). ${override} ${pin} ${tail}`
    : `Seen, not applied (lockfile ${installed}). ${override} ${tail}`;
}

/** A deferred row stays deferred. A later proven root upgrade is written back; reviewBy does not slide. */
async function promoteDeferredUpgrades(
  cwd: string,
  config: SupplywardenConfig,
  classified: CheckEntry[],
  registry: RegistryClient,
): Promise<{ wrote: boolean; messages: string[] }> {
  const messages: string[] = [];
  let wrote = false;
  for (const item of classified) {
    if (item.entry.strategy !== "defer") continue;
    if (item.entry.status !== "active") continue;
    if (item.statuses.includes("REMOVABLE") || item.statuses.includes("RESOLVED")) continue;

    const graph = analyzeNpmGraph(cwd, item.entry.package);
    const kind = mergeDependencyKind(undefined, graph.dependencyKind);
    const decision = await resolveUpgradeDecision(
      decide({
        graph: { ...graph, dependencyKind: kind },
        advisories: item.entry.advisories,
        config,
      }),
      lookupFromRegistry(registry),
      {
        vulnPackage: item.entry.package,
        advisories: item.entry.advisories,
        chains: graph.chains,
        dependencyKind: kind,
      },
    );
    if (waitRecheckOutcome(decision) !== "upgrade") continue;

    wrote = true;
    item.entry.strategy = "upgrade";
    item.entry.reason = decision.reason;
    item.entry.reviewReason = "Root upgrade now closes the advisory";
    item.decision = decision;
    const pm = resolvePackageManager(cwd);
    const displays = rootUpgradeCommands(pm, decision.upgradeTargets ?? []).map((c) => c.display);
    item.upgradeCommand = displays[0];
    item.upgradeCommands = displays.length ? displays : undefined;
    const statuses = item.statuses.filter((s) => s !== "DEFERRED");
    if (!statuses.length) statuses.push("OK");
    item.statuses = statuses;
    item.status = pickPrimary(statuses);
    const bump = formatUpgradeTargets(decision);
    const cmdText = displays.map((c) => `\`${c}\``).join(" then ");
    item.suggestedAction = cmdText
      ? `Previously seen. UPGRADE ${bump} now closes the advisory — run ${cmdText}`
      : `Previously seen. UPGRADE ${bump} now closes the advisory.`;
    messages.push(
      `DEFERRED ${item.entry.package}: now UPGRADE ${bump}${displays.length ? ` — ${displays.join(" then ")}` : ""}`,
    );
  }
  return { wrote, messages };
}

function formatNewFindingMessage(entry: CheckEntry): string {
  const installed = entry.installedVersions?.join(", ") || "?";
  const pkg = entry.entry.package;
  if (entry.decision?.strategy === "upgrade") {
    const breaking = breakingUpgradeNote(entry.decision);
    if (breaking) return `NEW ${pkg} (lockfile ${installed}): ${breaking}`;
    const bump = formatUpgradeTargets(entry.decision) || (entry.roots ?? []).join(", ") || pkg;
    const cmds = (entry.upgradeCommands ?? (entry.upgradeCommand ? [entry.upgradeCommand] : [])).join(" then ");
    return cmds
      ? `NEW ${pkg} (lockfile ${installed}): ${bump} — ${cmds}`
      : `NEW ${pkg} (lockfile ${installed}): ${bump}`;
  }
  if (entry.decision?.strategy === "wait") {
    return `NEW ${pkg} (lockfile ${installed}): WAIT — no override/upgrade this cycle`;
  }
  const pin = breakingPinNote(pkg, entry.installedVersions ?? [], entry.entry.forcedVersion);
  return pin
    ? `NEW ${pkg} (lockfile ${installed}): OVERRIDE ${pkg}@${entry.entry.forcedVersion} — ${pin}`
    : `NEW ${pkg} (lockfile ${installed}): OVERRIDE ${pkg}@${entry.entry.forcedVersion}`;
}

function newFindingAction(
  group: PackageAlertGroup,
  decision: Decision,
  roots: string[],
  kind: DependencyKind | undefined,
  upgradeCmds: string[],
  installed: string[],
  autoApplyRootUpgrade?: boolean,
): string {
  const kindTag = dependencyKindLabel(kind);
  const sev = group.maxSeverity.toUpperCase() + (kindTag ? ` (${kindTag})` : "");
  if (decision.strategy === "upgrade") {
    const breaking = breakingUpgradeNote(decision);
    if (breaking) return `New ${sev}: ${breaking}`;
    const targets = (decision.upgradeTargets ?? [])
      .map((t) => formatUpgradeTarget(t))
      .join(", ");
    const what = targets || roots.join(", ") || group.package;
    const cmdText = upgradeCmds.map((c) => `\`${c}\``).join(" then ");
    if (cmdText && !autoApplyRootUpgrade) {
      return `New ${sev}: UPGRADE ${what} — run ${cmdText}`;
    }
    if (cmdText && autoApplyRootUpgrade) {
      return `New ${sev}: UPGRADE ${what} — run \`supplywarden fix --apply\` (starts ${cmdText})`;
    }
    return `New ${sev}: UPGRADE ${what} — run \`supplywarden fix --apply\``;
  }
  if (decision.strategy === "wait") {
    return `New ${sev}: WAIT — no override or root upgrade this cycle. \`supplywarden fix --apply\` records the wait until reviewBy`;
  }
  const ver = decision.forcedVersion ?? group.forcedVersion;
  const pin = breakingPinNote(group.package, installed, ver);
  if (!ver || !specFloorSafe(ver, group.advisories)) {
    return `New ${sev}: ${group.package} has no safe override version — inspect with \`supplywarden why ${group.package}\` (not \`fix --apply\`)`;
  }
  const rootPart = roots.length ? ` (roots: ${roots.join(", ")})` : "";
  const breakPart = pin ? ` ${pin}` : "";
  return `New ${sev}: OVERRIDE ${group.package}@${ver}${rootPart} — run \`supplywarden fix --apply\`.${breakPart}`;
}

async function entryFromAuditGroup(
  cwd: string,
  group: PackageAlertGroup,
  config: SupplywardenConfig,
  registry?: RegistryClient,
): Promise<CheckEntry> {
  const graph = analyzeNpmGraph(cwd, group.package);
  const kind = mergeDependencyKind(group.dependencyKind, graph.dependencyKind);
  const decision = await resolveUpgradeDecision(
    decide({ graph: { ...graph, dependencyKind: kind }, advisories: group.advisories, config }),
    lookupFromRegistry(registry),
    { vulnPackage: group.package, advisories: group.advisories, chains: graph.chains, dependencyKind: kind },
  );
  const roots = graph.roots.map((r) => r.name);
  const chains = graph.chains.map((c) => c.path.join(" → "));
  const pm = resolvePackageManager(cwd);
  const upgradeCmds =
    decision.strategy === "upgrade"
      ? rootUpgradeCommands(pm, decision.upgradeTargets ?? [])
      : [];
  const upgradeDisplays = upgradeCmds.map((c) => c.display);
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
    packageManager: pm,
    manifestPath: group.manifestPath,
    createdAt: nowIso(),
    createdBy: "audit",
    reviewBy: nowIso(),
    reviewReason:
      decision.strategy === "wait"
        ? "Wait — no override/upgrade this cycle; re-open at reviewBy"
        : "New audit finding – run fix --apply to track",
    needsReview: true,
  };
  return {
    entry,
    status: "NEW",
    statuses: ["NEW"],
    suggestedAction: newFindingAction(
      group,
      decision,
      roots,
      kind,
      upgradeDisplays,
      graph.versions,
      config.autoApplyRootUpgrade,
    ),
    issues: [],
    roots,
    chains,
    installedVersions: graph.versions,
    decision,
    dependencyKind: kind,
    upgradeCommand: config.autoApplyRootUpgrade ? undefined : upgradeDisplays[0],
    upgradeCommands: config.autoApplyRootUpgrade ? undefined : upgradeDisplays,
  };
}
