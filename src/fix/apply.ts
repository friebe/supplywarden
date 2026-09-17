import { findDuplicate, dedupeOrSupersede } from "../validation/collisions.js";
import { assessImpact, estimateImpact } from "../validation/impact-diff.js";
import { blockingIssues, runPreApplyGate } from "../validation/override-gate.js";
import { runPostVerify } from "../validation/post-verify.js";
import { readMetadata, writeMetadata, newEntryId } from "../metadata/store.js";
import { syncOverridesToPackageJson, readPackageJson, writePackageJson } from "../metadata/sync.js";
import { detectPackageManager } from "../graph/npm.js";
import { addDaysIso, nowIso } from "../util/time.js";
import { restoreFiles, snapshotFiles } from "../util/snapshot.js";
import { actorName } from "../config.js";
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
    packageManager: detectPackageManager(cwd) === "unknown" ? "npm" : detectPackageManager(cwd),
    manifestPath: group.manifestPath,
    createdAt: duplicate?.createdAt ?? nowIso(),
    createdBy: actorName(),
    reviewBy: addDaysIso(config.defaultReviewDays),
    reviewReason: "Verify whether a root-package upgrade can replace this override",
    needsReview: false,
  };

  if (decision.strategy === "upgrade" && decision.upgradeTargets?.length) {
    bumpRootPackages(cwd, decision.upgradeTargets, group.manifestPath);
    messages.push(
      `Root packages bumped: ${decision.upgradeTargets
        .map((t) => (t.to ? `${t.name}@${t.from ?? "?"} → ${t.to}` : t.name))
        .join(", ")}`,
    );
  }

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

function bumpRootPackages(
  cwd: string,
  targets: Array<{ name: string; from?: string; to?: string }>,
  manifestPath: string,
): void {
  const pkg = readPackageJson(cwd, manifestPath);
  const bags = [
    pkg.dependencies as Record<string, string> | undefined,
    pkg.devDependencies as Record<string, string> | undefined,
    pkg.optionalDependencies as Record<string, string> | undefined,
  ];
  for (const t of targets) {
    if (!t.to) continue;
    for (const bag of bags) {
      if (!bag || !(t.name in bag)) continue;
      const current = bag[t.name] ?? "";
      const prefix = current.startsWith("~") ? "~" : "^";
      bag[t.name] = `${prefix}${t.to}`;
    }
  }
  writePackageJson(cwd, pkg, manifestPath);
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
