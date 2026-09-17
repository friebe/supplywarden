import { findDuplicate, dedupeOrSupersede } from "../validation/collisions.js";
import { assessImpact, estimateImpact } from "../validation/impact-diff.js";
import { blockingIssues, runPreApplyGate } from "../validation/override-gate.js";
import { runPostVerify } from "../validation/post-verify.js";
import { readMetadata, writeMetadata, newEntryId } from "../metadata/store.js";
import { syncOverridesToPackageJson } from "../metadata/sync.js";
import { resolvePackageManager } from "../graph/npm.js";
import { addDaysIso, nowIso } from "../util/time.js";
import { PROJECT_SNAPSHOT_FILES, restoreFiles, snapshotFiles } from "../util/snapshot.js";
import { actorName } from "../config.js";
import { createLiveInstall } from "../install/client.js";
import { rootUpgradeCommand } from "./upgrade-command.js";
import type {
  AuditClient,
  CommandResult,
  Decision,
  GraphAnalysis,
  InstallClient,
  MetadataEntry,
  PackageAlertGroup,
  RegistryClient,
  ReportModel,
  SupplywardenConfig,
} from "../types.js";

export type ApplyOptions = {
  cwd: string;
  config: SupplywardenConfig;
  group: PackageAlertGroup;
  graph: GraphAnalysis;
  decision: Decision;
  apply: boolean;
  skipInstall?: boolean;
  registry?: RegistryClient;
  audit?: AuditClient;
  install?: InstallClient;
};

export async function applyFix(opts: ApplyOptions): Promise<CommandResult> {
  const messages: string[] = [];
  const { cwd, config, group, graph, decision } = opts;
  const forcedVersion = decision.forcedVersion ?? group.forcedVersion;

  if (!forcedVersion) {
    const report = baseReport(opts, [], "No patched version in advisory");
    return {
      exitCode: 1,
      report,
      messages: [
        "Not writing package.json — no patched version that closes the advisory",
      ],
    };
  }

  const metadata = readMetadata(cwd, config);
  const issues = await runPreApplyGate({
    pkg: group.package,
    forcedVersion,
    graph,
    advisories: group.advisories,
    scope: decision.scope,
    existing: metadata.entries,
    registry: opts.registry,
  });

  const impact = assessImpact(estimateImpact(graph.chains.length, graph.roots.length), config);
  if (impact.blocked) {
    issues.push({
      code: "IMPACT_BLOCKED",
      message: `Lockfile-Impact ${impact.changedPackages} exceeds block threshold ${config.impactBlockThreshold}`,
      blocking: true,
    });
  }

  const blocked = blockingIssues(issues);
  const report = baseReport(opts, issues, "Pre-apply validation", { impact });

  if (decision.strategy === "upgrade") {
    return applyRootUpgrade(opts, { messages, blocked, report, impact });
  }

  if (!opts.apply) {
    messages.push("Dry-run: pass --apply to write package.json and security-metadata.json");
    return { exitCode: blocked.length ? 1 : 0, report, messages };
  }

  if (blocked.length) {
    return {
      exitCode: 1,
      report: { ...report, title: `ABGELEHNT: ${blocked[0]!.code}` },
      messages: [
        `Not writing package.json — ${blocked[0]!.code}`,
        ...blocked.map((i) => (i.hint ? `${i.message} (${i.hint})` : i.message)),
      ],
    };
  }

  if (impact.warning) {
    messages.push(
      `Impact: ${impact.changedPackages} packages (≥ warn threshold ${config.impactWarnThreshold})`,
    );
  }

  const files = [config.metadataPath, "package.json"];
  const snap = snapshotFiles(cwd, files);

  const duplicate = findDuplicate(metadata, group.package, group.advisories[0]?.ghsaId);
  const entry: MetadataEntry = {
    id: duplicate?.id ?? newEntryId(),
    status: "pending_verify",
    package: group.package,
    forcedVersion,
    scope: decision.scope,
    advisories: group.advisories,
    reason: decision.reason,
    strategy: decision.strategy,
    rootPackages: graph.roots.map((r) => r.name),
    dependencyChains: graph.chains.map((c) => c.path.join(" → ")),
    packageManager: resolvePackageManager(cwd),
    manifestPath: group.manifestPath,
    createdAt: duplicate?.createdAt ?? nowIso(),
    createdBy: actorName(),
    reviewBy: addDaysIso(config.defaultReviewDays),
    reviewReason: "Verify whether a root-package upgrade can replace this override",
    needsReview: false,
  };

  const { metadata: next } = dedupeOrSupersede(metadata, entry);
  writeMetadata(cwd, config, next);
  if (decision.strategy === "override") {
    syncOverridesToPackageJson(cwd, next, group.manifestPath);
  }

  if (!opts.skipInstall && opts.install) {
    const installed = await opts.install.install(cwd);
    if (!installed.ok) {
      restoreFiles(cwd, snap);
      persistApplyVerifyFailed(cwd, config, entry, decision.strategy, group.manifestPath, installed.error ?? "install failed");
      messages.push(installed.error ?? "npm install failed");
      return {
        exitCode: 1,
        report: { ...report, title: "VERIFY_FAILED peer conflict" },
        messages,
        writtenFiles: [config.metadataPath, "package.json"],
      };
    }
  }

  const post = await runPostVerify({
    cwd,
    pkg: group.package,
    forcedVersion,
    advisories: group.advisories,
    audit: opts.audit,
  });
  const postBlocked = blockingIssues(post);

  if (postBlocked.length && !opts.skipInstall) {
    restoreFiles(cwd, snap);
    persistApplyVerifyFailed(
      cwd,
      config,
      entry,
      decision.strategy,
      group.manifestPath,
      postBlocked.map((i) => i.message).join("; "),
    );
    messages.push(...postBlocked.map((i) => i.message));
    return {
      exitCode: 1,
      report: { ...report, title: "VERIFY_FAILED", validation: [...issues, ...post] },
      messages,
      writtenFiles: [config.metadataPath, "package.json"],
    };
  }

  const verified = readMetadata(cwd, config);
  const saved = verified.entries.find((e) => e.id === entry.id);
  if (saved) saved.status = "active";
  writeMetadata(cwd, config, verified);

  messages.push(`Entry ${entry.id} active (${decision.strategy} ${group.package}@${forcedVersion})`);
  return {
    exitCode: 0,
    report: { ...report, title: `Applied ${group.package}@${forcedVersion}` },
    messages,
    writtenFiles: [config.metadataPath, "package.json"],
  };
}

function persistApplyVerifyFailed(
  cwd: string,
  config: SupplywardenConfig,
  entry: MetadataEntry,
  strategy: Decision["strategy"],
  manifestPath: string,
  error: string,
): void {
  entry.status = "verify_failed";
  entry.resolvedAt = nowIso();
  entry.resolvedBy = actorName();
  entry.resolution = `verify-failed: ${error}`;
  const meta = readMetadata(cwd, config);
  const { metadata: next } = dedupeOrSupersede(meta, entry);
  writeMetadata(cwd, config, next);
  if (strategy === "override") {
    syncOverridesToPackageJson(cwd, next, manifestPath);
  }
}

async function applyRootUpgrade(
  opts: ApplyOptions,
  ctx: {
    messages: string[];
    blocked: import("../types.js").ValidationIssue[];
    report: ReportModel;
    impact: import("../types.js").ImpactDiff;
  },
): Promise<CommandResult> {
  const { cwd, config, group, decision } = opts;
  const { messages, blocked, report, impact } = ctx;
  const pm = resolvePackageManager(cwd);
  const command = rootUpgradeCommand(pm, decision.upgradeTargets ?? []);

  if (impact.warning) {
    messages.push(
      `Impact: ${impact.changedPackages} packages (≥ warn threshold ${config.impactWarnThreshold})`,
    );
  }
  if (command) {
    messages.push(`Package manager: ${command.display}`);
  }

  if (!opts.apply) {
    messages.push(
      command?.kind === "nx"
        ? "Dry-run: pass --apply to start Nx migrate (Nx asks which packages to update)"
        : "Dry-run: pass --apply to run the package-manager upgrade (package.json is not edited here)",
    );
    return { exitCode: blocked.length ? 1 : 0, report, messages };
  }

  if (blocked.length) {
    return {
      exitCode: 1,
      report: { ...report, title: `ABGELEHNT: ${blocked[0]!.code}` },
      messages: [
        `Not installing — ${blocked[0]!.code}`,
        ...blocked.map((i) => (i.hint ? `${i.message} (${i.hint})` : i.message)),
        ...messages,
      ],
    };
  }

  if (!command) {
    messages.push("No upgrade version resolved — not writing package.json");
    return { exitCode: 1, report: { ...report, title: "No upgrade version" }, messages };
  }

  if (opts.skipInstall) {
    messages.push(`Not writing package.json — run \`${command.display}\``);
    return { exitCode: 1, report: { ...report, title: "Root upgrade needs install" }, messages };
  }

  const install = opts.install ?? createLiveInstall();
  if (!install.runCommand) {
    messages.push(`Not writing package.json — run \`${command.display}\``);
    return { exitCode: 1, report: { ...report, title: "Root upgrade needs install" }, messages };
  }

  const snap = snapshotFiles(cwd, [...PROJECT_SNAPSHOT_FILES, group.manifestPath]);
  const installed = await install.runCommand(cwd, command.file, command.args);
  if (!installed.ok) {
    restoreFiles(cwd, snap);
    messages.push(installed.error ?? `${command.display} failed`);
    return {
      exitCode: 1,
      report: { ...report, title: "VERIFY_FAILED peer conflict" },
      messages,
    };
  }

  if (command.kind === "nx") {
    messages.push(
      `Started ${command.display} — Nx owns package selection. If it wrote migrations.json, install then \`npx nx migrate --run-migrations\`.`,
    );
    return {
      exitCode: 0,
      report: { ...report, title: `Nx migrate ${command.args[command.args.length - 1] ?? ""}`.trim() },
      messages,
      writtenFiles: [group.manifestPath],
    };
  }

  const post = await runPostVerify({
    cwd,
    pkg: group.package,
    forcedVersion: decision.forcedVersion ?? group.forcedVersion ?? "",
    advisories: group.advisories,
    audit: opts.audit,
  });
  const postBlocked = blockingIssues(post);
  if (postBlocked.length) {
    restoreFiles(cwd, snap);
    messages.push(...postBlocked.map((i) => i.message));
    return {
      exitCode: 1,
      report: { ...report, title: "VERIFY_FAILED", validation: [...(report.validation ?? []), ...post] },
      messages,
    };
  }

  messages.push(`Installed via ${command.display} (no override written)`);
  return {
    exitCode: 0,
    report: { ...report, title: `Upgraded via ${pm}` },
    messages,
    writtenFiles: [group.manifestPath],
  };
}

function baseReport(
  opts: ApplyOptions,
  issues: ApplyOptions extends never ? never : import("../types.js").ValidationIssue[],
  title: string,
  extra: Partial<ReportModel> = {},
): ReportModel {
  return {
    title,
    generatedAt: nowIso(),
    cwd: opts.cwd,
    summary: {
      package: opts.group.package,
      strategy: opts.decision.strategy,
      advisories: opts.group.advisories.length,
    },
    entries: [],
    groups: [opts.group],
    decision: opts.decision,
    validation: issues,
    ...extra,
  };
}
