import { blockingIssues, runPreApplyGate } from "../validation/override-gate.js";
import { runPostVerify } from "../validation/post-verify.js";
import { extractExistingOverrides, readPackageJson, upsertOverride } from "../metadata/sync.js";
import { nowIso } from "../util/time.js";
import { extraSnapshotFiles } from "../graph/workspace.js";
import { PROJECT_SNAPSHOT_FILES, restoreFiles, snapshotFiles } from "../util/snapshot.js";
import { createLiveInstall } from "../install/client.js";
import { quotedUpgradeCommands, rootUpgradeCommands } from "./upgrade-command.js";
import {
  breakingPinNote,
  breakingUpgradeNote,
  formatUpgradeTargets,
  pinLabel,
  safeDirectCopyNote,
} from "../decision/engine.js";
import { resolvePackageManager } from "../graph/npm.js";
import type {
  AuditClient,
  CommandResult,
  Decision,
  GraphAnalysis,
  InstallClient,
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
  const { cwd, group, graph, decision } = opts;
  const reportEarly = baseReport(opts, [], "Pre-apply validation");

  if (decision.strategy === "wait") {
    return applyWait(opts, reportEarly);
  }

  const forcedVersion = decision.forcedVersion ?? group.forcedVersion;

  if (!forcedVersion) {
    const report = baseReport(opts, [], "No patched version in advisory");
    return {
      exitCode: 1,
      report,
      messages: ["Not writing package.json — no patched version that closes the advisory"],
    };
  }

  const existing = readPins(cwd);
  const scopes = decision.scopes?.length ? decision.scopes : [decision.scope];
  const issues = (
    await Promise.all(
      scopes.map((scope) =>
        runPreApplyGate({
          pkg: group.package,
          forcedVersion,
          graph,
          advisories: group.advisories,
          scope,
          existing,
          registry: opts.registry,
        }),
      ),
    )
  ).flat();
  const seenIssue = new Set<string>();
  const uniqueIssues = issues.filter((issue) => {
    const key = `${issue.code}:${issue.message}`;
    if (seenIssue.has(key)) return false;
    seenIssue.add(key);
    return true;
  });

  const blocked = blockingIssues(uniqueIssues);
  const report = baseReport(opts, uniqueIssues, "Pre-apply validation");

  if (decision.strategy === "upgrade") {
    return applyRootUpgrade(opts, { messages, blocked, report });
  }

  const pinNote = breakingPinNote(group.package, graph.versions, forcedVersion);
  if (pinNote) messages.push(pinNote);
  const directNote = safeDirectCopyNote(graph, group.advisories, scopes);
  if (directNote) messages.push(directNote);

  const where = pinLabel(group.package, forcedVersion, scopes);
  if (!opts.apply) {
    messages.push(`Dry-run: ${where} Pass --apply to write it into package.json.`);
    return { exitCode: blocked.length ? 1 : 0, report, messages };
  }

  if (blocked.length) {
    return {
      exitCode: 1,
      report: { ...report, title: `Rejected: ${blocked[0]!.code}` },
      messages: [
        `Not writing package.json — ${blocked[0]!.code}`,
        ...blocked.map((i) => (i.hint ? `${i.message} (${i.hint})` : i.message)),
      ],
    };
  }

  const snap = snapshotFiles(cwd, [...PROJECT_SNAPSHOT_FILES, ...extraSnapshotFiles(cwd)]);
  for (const scope of scopes) {
    upsertOverride(
      cwd,
      { package: group.package, version: forcedVersion, scope },
      group.manifestPath,
    );
  }

  if (!opts.skipInstall && opts.install) {
    const installed = await opts.install.install(cwd);
    if (!installed.ok) {
      restoreFiles(cwd, snap);
      messages.push(installed.error ?? "npm install failed");
      return {
        exitCode: 1,
        report: { ...report, title: "Install failed" },
        messages,
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
    messages.push(...postBlocked.map((i) => i.message));
    return {
      exitCode: 1,
      report: { ...report, title: "Install failed", validation: [...uniqueIssues, ...post] },
      messages,
    };
  }

  messages.push(`Wrote ${where} package.json was updated.`);
  return {
    exitCode: 0,
    report: { ...report, title: `Applied ${group.package}@${forcedVersion}` },
    messages,
    writtenFiles: ["package.json"],
  };
}

function readPins(cwd: string): Array<{ package: string; forcedVersion: string }> {
  try {
    return extractExistingOverrides(readPackageJson(cwd)).map((pin) => ({
      package: pin.package,
      forcedVersion: pin.version,
    }));
  } catch {
    return [];
  }
}

function noteBreakingUpgradeSkip(messages: string[], decision: Decision) {
  const note = breakingUpgradeNote(decision);
  if (note) messages.push(note);
}

function applyWait(opts: ApplyOptions, report: ReportModel): CommandResult {
  const { group, decision } = opts;
  return {
    exitCode: 0,
    report: { ...report, title: `WAIT ${group.package}` },
    messages: [`WAIT: ${decision.reason}. No override written.`],
  };
}

async function applyRootUpgrade(
  opts: ApplyOptions,
  ctx: {
    messages: string[];
    blocked: import("../types.js").ValidationIssue[];
    report: ReportModel;
  },
): Promise<CommandResult> {
  const { cwd, config, group, decision } = opts;
  const { messages, blocked, report } = ctx;
  const pm = resolvePackageManager(cwd);
  const commands = rootUpgradeCommands(pm, decision.upgradeTargets ?? []);
  const quoted = quotedUpgradeCommands(commands);
  const hasNx = commands.some((c) => c.kind === "nx");
  const hasMigrate = commands.some((c) => c.kind === "migrate");
  const hasInstall = commands.some((c) => c.kind === "install");
  const nx = commands.find((c) => c.kind === "nx");
  const installCmd = commands.find((c) => c.kind === "install");

  if (commands.length) {
    const bump = formatUpgradeTargets(decision);
    if (bump) messages.push(`Upgrade ${bump}`);
    messages.push(`Package manager: ${commands.map((c) => c.display).join(" then ")}`);
  }

  if (!commands.length) {
    messages.push("No upgrade version resolved — not writing package.json");
    return { exitCode: 1, report: { ...report, title: "No upgrade version" }, messages };
  }

  if (commands.every((command) => command.kind === "catalog")) {
    messages.push(`Catalog edit is a suggestion — ${quoted}`);
    return {
      exitCode: blocked.length ? 1 : 0,
      report: { ...report, title: "Catalog edit suggested" },
      messages,
    };
  }

  if (!opts.apply) {
    noteBreakingUpgradeSkip(messages, decision);
    messages.push(
      config.autoApplyRootUpgrade
        ? dryRunApplyLine({ hasNx, hasInstall, hasMigrate, install: installCmd?.display, quoted })
        : `Dry-run: root upgrade is a suggestion — run ${quoted} (set autoApplyRootUpgrade to run it from fix --apply)`,
    );
    return { exitCode: blocked.length ? 1 : 0, report, messages };
  }

  if (!config.autoApplyRootUpgrade) {
    noteBreakingUpgradeSkip(messages, decision);
    messages.push(
      `Root upgrade is a suggestion — run ${quoted} (set autoApplyRootUpgrade to run it from fix --apply)`,
    );
    return { exitCode: 0, report: { ...report, title: "Root upgrade suggested" }, messages };
  }

  if (blocked.length) {
    return {
      exitCode: 1,
      report: { ...report, title: `Rejected: ${blocked[0]!.code}` },
      messages: [
        `Not installing — ${blocked[0]!.code}`,
        ...blocked.map((i) => (i.hint ? `${i.message} (${i.hint})` : i.message)),
        ...messages,
      ],
    };
  }

  if (opts.skipInstall) {
    noteBreakingUpgradeSkip(messages, decision);
    messages.push(`Not writing package.json — run ${quoted}`);
    return { exitCode: 1, report: { ...report, title: "Root upgrade needs install" }, messages };
  }

  const install = opts.install ?? createLiveInstall();
  if (!install.runCommand) {
    noteBreakingUpgradeSkip(messages, decision);
    messages.push(`Not writing package.json — run ${quoted}`);
    return { exitCode: 1, report: { ...report, title: "Root upgrade needs install" }, messages };
  }

  const snap = snapshotFiles(cwd, [
    ...PROJECT_SNAPSHOT_FILES,
    ...extraSnapshotFiles(cwd),
    group.manifestPath,
  ]);
  for (const command of commands) {
    if (command.kind === "catalog") {
      messages.push(command.display);
      continue;
    }
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
  }

  if (hasNx || hasMigrate) {
    if (hasInstall) {
      messages.push(`Installed via ${installCmd!.display} (no override written)`);
    }
    if (hasNx) {
      messages.push(
        `Started ${nx!.display} — Nx owns package selection. If it wrote migrations.json, install then \`npx nx migrate --run-migrations\`.`,
      );
    }
    const migrate = commands
      .filter((command) => command.kind === "migrate")
      .map((command) => command.display)
      .join(" then ");
    if (migrate) {
      messages.push(`Started ${migrate}. The migration CLI owns which packages move.`);
    }
    const title = hasNx
      ? hasInstall
        ? `Upgraded via ${pm} then Nx migrate`
        : `Nx migrate ${nx!.args[nx!.args.length - 1] ?? ""}`.trim()
      : `Upgraded via ${migrate}`;
    return {
      exitCode: 0,
      report: { ...report, title },
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
      report: {
        ...report,
        title: "VERIFY_FAILED",
        validation: [...(report.validation ?? []), ...post],
      },
      messages,
    };
  }

  messages.push(`Installed via ${installCmd!.display} (no override written)`);
  return {
    exitCode: 0,
    report: { ...report, title: `Upgraded via ${pm}` },
    messages,
    writtenFiles: [group.manifestPath],
  };
}

function dryRunApplyLine(opts: {
  hasNx: boolean;
  hasInstall: boolean;
  hasMigrate: boolean;
  install?: string;
  quoted: string;
}): string {
  if (opts.hasNx && !opts.hasInstall) {
    return "Dry-run: pass --apply to start Nx migrate (Nx asks which packages to update)";
  }
  if (opts.hasNx && opts.hasInstall) {
    return `Dry-run: pass --apply to run ${opts.install} then start Nx migrate (Nx asks which packages to update)`;
  }
  if (opts.hasMigrate) return `Dry-run: pass --apply to run ${opts.quoted}`;
  return "Dry-run: pass --apply to run the package-manager upgrade (package.json is not edited here)";
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
