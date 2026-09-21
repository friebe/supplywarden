import { analyzeNpmGraph, resolvePackageManager } from "../graph/npm.js";
import {
  decide,
  firstSafeForcedVersion,
  formatUpgradeTarget,
  formatUpgradeTargets,
  lookupFromRegistry,
  resolveUpgradeDecision,
  stillVulnerable,
} from "../decision/engine.js";
import { listOverridesToProbe } from "./check.js";
import { specFloorSafe } from "../util/semver-spec.js";
import { readMetadata, writeMetadata } from "../metadata/store.js";
import { deleteOverrideFromManifest, syncOverridesToPackageJson } from "../metadata/sync.js";
import { createLiveAudit, filterFindings } from "../audit/client.js";
import { createLiveInstall } from "../install/client.js";
import { createLiveRegistry } from "../registry/verify.js";
import { quotedUpgradeCommands, rootUpgradeCommands, type RootUpgradeCommand } from "../fix/upgrade-command.js";
import { PROJECT_SNAPSHOT_FILES, restoreFiles, snapshotFiles } from "../util/snapshot.js";
import { addDaysIso, nowIso } from "../util/time.js";
import { actorName, loadConfig } from "../config.js";
import type {
  AuditClient,
  CheckEntry,
  CommandResult,
  Decision,
  InstallClient,
  RegistryClient,
  SupplywardenConfig,
} from "../types.js";

function leftoverHeuristic(entry: CheckEntry): boolean {
  return (
    entry.removableReason === "not-in-tree" ||
    entry.removableReason === "already-at-patched"
  );
}

function persistVerifyFailed(
  cwd: string,
  config: SupplywardenConfig,
  candidate: CheckEntry,
  error: string,
): boolean {
  const meta = readMetadata(cwd, config);
  const entry =
    meta.entries.find((e) => e.id === candidate.entry.id) ??
    meta.entries.find(
      (e) =>
        e.package === candidate.entry.package &&
        e.status !== "resolved" &&
        e.status !== "superseded",
    );
  if (!entry) return false;
  entry.status = "verify_failed";
  entry.resolvedAt = nowIso();
  entry.resolvedBy = actorName();
  entry.resolution = `verify-failed: ${error}`;
  writeMetadata(cwd, config, meta);
  return true;
}

function persistVerifyKeep(
  cwd: string,
  config: SupplywardenConfig,
  candidate: CheckEntry,
  why: string,
): boolean {
  const meta = readMetadata(cwd, config);
  const entry =
    meta.entries.find((e) => e.id === candidate.entry.id) ??
    meta.entries.find(
      (e) =>
        e.package === candidate.entry.package &&
        e.status !== "resolved" &&
        e.status !== "superseded",
    );
  if (!entry) return false;
  entry.status = "active";
  entry.resolvedAt = nowIso();
  entry.resolvedBy = actorName();
  entry.resolution = `verify-keep: ${why}`;
  entry.reviewBy = addDaysIso(config.defaultReviewDays);
  entry.reviewReason = "Verified — override still required";
  entry.needsReview = false;
  writeMetadata(cwd, config, meta);
  return true;
}

function overrideConflictPackage(error: string): string | undefined {
  const match = error.match(/Override for ([^\s@]+)@/i);
  return match?.[1];
}

export async function runVerify(opts: {
  cwd: string;
  package?: string;
  apply?: boolean;
  skipInstall?: boolean;
  audit?: AuditClient;
  install?: InstallClient;
  registry?: RegistryClient;
}): Promise<CommandResult> {
  const cwd = opts.cwd;
  const config = loadConfig(cwd);
  const pkg = opts.package;
  const candidates = listOverridesToProbe(cwd, config, pkg);
  const classified = candidates;

  if (!candidates.length) {
    const messages = pkg
      ? [
          `verify: no override for ${pkg} in package.json or security-metadata.json`,
          `Inspect with \`supplywarden why ${pkg}\`. Without a package name, verify only probes REMOVABLE leftovers.`,
        ]
      : [
          "verify: no REMOVABLE/RESOLVED overrides to probe",
          "Pass a package to try dropping that one override (`supplywarden verify qs`), even if check has not marked it REMOVABLE.",
        ];
    return {
      exitCode: pkg ? 1 : 0,
      messages,
      report: {
        title: pkg ? `supplywarden verify ${pkg} – nothing to probe` : "supplywarden verify – nothing to probe",
        generatedAt: nowIso(),
        cwd,
        summary: { probed: 0 },
        entries: classified,
      },
    };
  }

  const audit = opts.audit ?? createLiveAudit();
  const install = opts.install ?? createLiveInstall();
  const files = [...PROJECT_SNAPSHOT_FILES, config.metadataPath];
  const snap = snapshotFiles(cwd, files);
  let written: string[] = [];
  const probed: CheckEntry[] = [];
  const messages: string[] = [
    pkg
      ? `supplywarden verify ${pkg} – probing 1 override (drop → install → audit)`
      : `supplywarden verify – ${candidates.length} candidate(s)`,
  ];
  let needResync = false;
  const failures: Array<{ candidate: CheckEntry; error: string }> = [];
  const keeps: Array<{ candidate: CheckEntry; why: string }> = [];
  const keepUpgrades: RootUpgradeCommand[] = [];
  const registry = opts.registry ?? createLiveRegistry(cwd);

  for (const candidate of candidates) {
    restoreFiles(cwd, snap);
    const working = readMetadata(cwd, config);
    const entry = working.entries.find((e) => e.id === candidate.entry.id);
    if (entry) {
      entry.status = "resolved";
      entry.resolvedAt = nowIso();
      entry.resolution = "verify-probe";
      writeMetadata(cwd, config, working);
      syncOverridesToPackageJson(cwd, working, entry.manifestPath);
    } else {
      deleteOverrideFromManifest(cwd, candidate.entry.package);
    }

    let installedOk = opts.skipInstall || leftoverHeuristic(candidate);
    if (!opts.skipInstall && !leftoverHeuristic(candidate)) {
      const installed = await install.install(cwd);
      if (!installed.ok) {
        const conflictPkg = overrideConflictPackage(installed.error ?? "");
        const unrelated = Boolean(conflictPkg && conflictPkg !== candidate.entry.package);
        restoreFiles(cwd, snap);
        if (!unrelated) {
          failures.push({ candidate, error: installed.error ?? "install failed" });
          probed.push({
            ...candidate,
            status: "VERIFY_FAILED",
            statuses: ["VERIFY_FAILED"],
            verifyOutcome: "VERIFY_FAILED",
            suggestedAction: `Install failed — keep override (${installed.error ?? "install failed"}); retry with \`supplywarden verify ${candidate.entry.package}\``,
          });
          messages.push(`${candidate.entry.package}: VERIFY_FAILED (install failed)`);
          continue;
        }
        messages.push(
          `${candidate.entry.package}: install skipped (unrelated override conflict: ${conflictPkg})`,
        );
      } else {
        installedOk = true;
        needResync = true;
      }
    }

    const graph = analyzeNpmGraph(cwd, candidate.entry.package);
    const auditResult = await audit.audit(cwd);
    const pkgFindings = filterFindings(auditResult.vulnerabilities, config.audit.minSeverity).filter(
      (f) => f.package === candidate.entry.package,
    );
    const stillVuln = graph.versions.filter((v) =>
      candidate.entry.advisories.length
        ? stillVulnerable(v, candidate.entry.advisories)
        : false,
    );

    const auditFailed = Boolean(auditResult.error);
    const keep =
      pkgFindings.length > 0 ||
      (auditFailed && stillVuln.length > 0) ||
      (auditFailed && !leftoverHeuristic(candidate) && installedOk);

    restoreFiles(cwd, snap);

    if (keep) {
      const weak =
        candidate.entry.advisories.length > 0 &&
        !specFloorSafe(candidate.entry.forcedVersion, candidate.entry.advisories);
      const need = firstSafeForcedVersion(candidate.entry.advisories);
      const why = pkgFindings.length
        ? `audit still reports ${pkgFindings.length} finding(s)`
        : auditFailed && stillVuln.length
          ? `audit failed and lockfile still has version(s) matching stored advisories: ${stillVuln.join(", ")}`
          : `audit failed: ${auditResult.error}`;
      const decision = await resolveUpgradeDecision(
        decide({ graph, advisories: candidate.entry.advisories, config }),
        lookupFromRegistry(registry),
        {
          vulnPackage: candidate.entry.package,
          advisories: candidate.entry.advisories,
          chains: graph.chains,
          dependencyKind: graph.dependencyKind,
        },
      );
      const pm = resolvePackageManager(cwd);
      const upgradeCmds =
        decision.strategy === "upgrade"
          ? rootUpgradeCommands(pm, decision.upgradeTargets ?? [])
          : [];
      const upgradeDisplays = upgradeCmds.map((c) => c.display);
      const suggestedAction = keepSuggestedAction({
        pkg: candidate.entry.package,
        why,
        weak,
        forced: candidate.entry.forcedVersion,
        need,
        decision,
        roots: graph.roots.map((r) => r.name),
        upgradeDisplays,
        autoApply: config.autoApplyRootUpgrade,
        threshold: config.upgradeRootThreshold,
      });
      for (const command of upgradeCmds) {
        if (!keepUpgrades.some((c) => c.display === command.display)) keepUpgrades.push(command);
      }
      probed.push({
        ...candidate,
        status: "OK",
        statuses: ["OK"],
        verifyOutcome: "KEEP",
        weakOverride: weak,
        decision,
        roots: graph.roots.map((r) => r.name),
        suggestedAction,
        upgradeCommand: config.autoApplyRootUpgrade || !upgradeDisplays.length ? undefined : upgradeDisplays[0],
        upgradeCommands: config.autoApplyRootUpgrade || !upgradeDisplays.length ? undefined : upgradeDisplays,
      });
      messages.push(
        upgradeDisplays.length
          ? `${candidate.entry.package}: KEEP (${why}); UPGRADE ${formatUpgradeTargets(decision) || graph.roots.map((r) => r.name).join(", ")} — ${upgradeDisplays.join(" then ")}`
          : weak
            ? `${candidate.entry.package}: KEEP (weak override ${candidate.entry.forcedVersion}; run fix --apply)`
            : `${candidate.entry.package}: KEEP (${why})`,
      );
      keeps.push({ candidate, why });
    } else {
      probed.push({
        ...candidate,
        verifyOutcome: "CONFIRMED_REMOVABLE",
        suggestedAction: graph.inTree
          ? `Verify confirmed: override can be removed — run \`supplywarden verify ${candidate.entry.package} --apply\``
          : `Verify confirmed: package is no longer in the tree — run \`supplywarden verify ${candidate.entry.package} --apply\``,
      });
      messages.push(`${candidate.entry.package}: CONFIRMED_REMOVABLE`);
    }
  }

  restoreFiles(cwd, snap);

  if (needResync && !opts.skipInstall && !opts.apply) {
    await install.install(cwd);
  }

  for (const item of failures) {
    if (persistVerifyFailed(cwd, config, item.candidate, item.error)) {
      written = [config.metadataPath];
    }
  }
  for (const item of keeps) {
    if (persistVerifyKeep(cwd, config, item.candidate, item.why)) {
      written = [config.metadataPath];
    }
  }
  if (
    opts.apply &&
    config.autoApplyRootUpgrade &&
    !opts.skipInstall &&
    keepUpgrades.length &&
    install.runCommand
  ) {
    const quoted = quotedUpgradeCommands(keepUpgrades);
    let upgradeOk = true;
    for (const command of keepUpgrades) {
      const ran = await install.runCommand(cwd, command.file, command.args);
      if (!ran.ok) {
        upgradeOk = false;
        messages.push(ran.error ?? `${command.display} failed`);
        break;
      }
    }
    if (upgradeOk) {
      messages.push(`Ran ${quoted} (override kept until the next check)`);
    }
  } else if (opts.apply && !config.autoApplyRootUpgrade && keepUpgrades.length) {
    messages.push(
      `Root upgrade is a suggestion — run ${quotedUpgradeCommands(keepUpgrades)} (set autoApplyRootUpgrade to run it from verify --apply)`,
    );
  }
  const confirmed = probed.filter((p) => p.verifyOutcome === "CONFIRMED_REMOVABLE");
  if (opts.apply && confirmed.length) {
    const next = readMetadata(cwd, config);
    for (const item of confirmed) {
      const entry = next.entries.find((e) => e.id === item.entry.id);
      if (entry) {
        entry.status = "resolved";
        entry.resolvedAt = nowIso();
        entry.resolvedBy = actorName();
        entry.resolution = `verify-confirmed: ${item.removableReason ?? "probe-clear"}`;
      }
      deleteOverrideFromManifest(cwd, item.entry.package);
    }
    writeMetadata(cwd, config, next);
    written = [config.metadataPath, "package.json"];
    messages.push(`Applied ${confirmed.length} confirmed removal(s)`);
  } else if (opts.apply && !confirmed.length && !keepUpgrades.length) {
    messages.push(
      "verify --apply: nothing confirmed as removable (install/audit kept every candidate). See KEEP/VERIFY_FAILED above.",
    );
  } else if (!opts.apply && confirmed.length) {
    messages.push("Dry-run: pass --apply to drop confirmed overrides");
  }

  const failed = probed.some((p) => p.verifyOutcome === "VERIFY_FAILED");

  return {
    exitCode: failed ? 1 : 0,
    messages,
    writtenFiles: written,
    report: {
      title: `supplywarden verify – ${probed.length} probed`,
      generatedAt: nowIso(),
      cwd,
      summary: {
        probed: probed.length,
        confirmed: confirmed.length,
        keep: probed.filter((p) => p.verifyOutcome === "KEEP").length,
        verifyFailed: probed.filter((p) => p.verifyOutcome === "VERIFY_FAILED").length,
      },
      entries: probed,
    },
  };
}

function keepSuggestedAction(opts: {
  pkg: string;
  why: string;
  weak: boolean;
  forced: string;
  need?: string;
  decision: Decision;
  roots: string[];
  upgradeDisplays: string[];
  autoApply: boolean;
  threshold: number;
}): string {
  if (opts.decision.strategy === "upgrade") {
    const what =
      formatUpgradeTargets(opts.decision) ||
      opts.decision.upgradeTargets?.map(formatUpgradeTarget).join(", ") ||
      opts.roots.join(", ") ||
      opts.pkg;
    const cmdText = opts.upgradeDisplays.map((c) => `\`${c}\``).join(" then ");
    const n = opts.roots.length || 1;
    if (cmdText && !opts.autoApply) {
      return `Keep override — ${opts.why}. ${n} root(s) ≤ threshold ${opts.threshold}: UPGRADE ${what} — run ${cmdText}`;
    }
    if (cmdText && opts.autoApply) {
      return `Keep override — ${opts.why}. UPGRADE ${what} — run \`supplywarden verify ${opts.pkg} --apply\` (starts ${cmdText})`;
    }
    return `Keep override — ${opts.why}. ${n} root(s) ≤ threshold ${opts.threshold}: prefer upgrading ${opts.roots.join(", ") || what}`;
  }
  if (opts.decision.strategy === "wait") {
    return `Keep override — ${opts.why}; inspect with \`supplywarden why ${opts.pkg}\``;
  }
  if (opts.weak) {
    return `Override ${opts.forced} does not close the advisory (need ${opts.need ?? "a patched version"}). Keeping it is a no-op — run \`supplywarden fix --apply\`, not verify --apply`;
  }
  return `Keep override — ${opts.why}; inspect with \`supplywarden why ${opts.pkg}\``;
}
