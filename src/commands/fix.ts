import { loadConfig } from "../config.js";
import {
  alertsFromInput,
  groupAlerts,
  loadAlertFile,
} from "../alerts/dependabot.js";
import { decide, resolveUpgradeDecision } from "../decision/engine.js";
import { analyzeNpmGraph } from "../graph/npm.js";
import { applyFix } from "../fix/apply.js";
import { createLiveRegistry } from "../registry/verify.js";
import { createLiveInstall } from "../install/client.js";
import { createLiveAudit, filterFindings, findingsToGroups } from "../audit/client.js";
import { listDropCandidates } from "./check.js";
import { nowIso } from "../util/time.js";
import type { AuditClient, CommandResult, InstallClient, PackageAlertGroup, RegistryClient } from "../types.js";

export async function runAnalyze(opts: {
  cwd: string;
  alertPath?: string;
  registry?: RegistryClient;
  enableAudit?: boolean;
  audit?: AuditClient;
}): Promise<CommandResult> {
  return runFix({ ...opts, apply: false });
}

export async function runFix(opts: {
  cwd: string;
  alertPath?: string;
  apply?: boolean;
  skipInstall?: boolean;
  registry?: RegistryClient;
  enableAudit?: boolean;
  audit?: AuditClient;
  install?: InstallClient;
}): Promise<CommandResult> {
  const cwd = opts.cwd;
  const config = loadConfig(cwd);
  const groupsResult = await loadGroups(opts, cwd, config.audit.minSeverity);

  if ("error" in groupsResult) {
    return {
      exitCode: 1,
      messages: [groupsResult.error],
      report: {
        title: "analyze: empty",
        generatedAt: nowIso(),
        cwd,
        summary: { groups: 0 },
        entries: [],
      },
    };
  }

  const groups = groupsResult.groups;
  if (!groups.length) {
    const removable = listDropCandidates(cwd, config);
    const hint = removable.length
      ? `${removable.length} existing override(s) are REMOVABLE (${removable.map((e) => e.entry.package).join(", ")}) — run \`supplywarden verify --apply\` to drop them. \`fix --apply\` is only for new findings.`
      : opts.alertPath
        ? "No package alerts found in input"
        : "Audit found no vulnerabilities at the configured minimum severity";
    return {
      exitCode: 1,
      messages: [hint],
      report: {
        title: "analyze: empty",
        generatedAt: nowIso(),
        cwd,
        summary: { groups: 0, removable: removable.length },
        entries: removable,
      },
    };
  }

  const results: CommandResult[] = [];
  for (const group of groups) {
    const graph = analyzeNpmGraph(cwd, group.package);
    group.installedVersion = graph.versions[0];
    const registry = opts.registry ?? createLiveRegistry();
    const decision = await resolveUpgradeDecision(
      decide({ graph, advisories: group.advisories, config }),
      {
        latestVersion: registry.latestVersion?.bind(registry),
        getLatestMatching: registry.getLatestMatching?.bind(registry),
      },
    );
    const result = await applyFix({
      cwd,
      config,
      group,
      graph,
      decision,
      apply: Boolean(opts.apply),
      skipInstall: opts.skipInstall ?? true,
      registry,
      install: opts.install ?? createLiveInstall(),
    });
    results.push(result);
  }

  const failed = results.find((r) => r.exitCode !== 0);
  const mergedMessages = results.flatMap((r) => r.messages);
  const first = results[0]!;
  first.report.groups = groups;
  first.messages = mergedMessages;
  if (groups.length > 1) {
    first.report.title = `${groups.length} package group(s)`;
    first.report.summary = {
      ...first.report.summary,
      groups: groups.length,
      advisories: groups.reduce((n, g) => n + g.advisories.length, 0),
    };
  }
  return failed ? { ...first, exitCode: failed.exitCode } : first;
}

async function loadGroups(
  opts: {
    alertPath?: string;
    enableAudit?: boolean;
    audit?: AuditClient;
  },
  cwd: string,
  minSeverity: import("../types.js").Severity,
): Promise<{ groups: PackageAlertGroup[] } | { error: string }> {
  if (opts.alertPath) {
    const raw = loadAlertFile(opts.alertPath);
    return { groups: groupAlerts(alertsFromInput(raw)) };
  }

  const auditEnabled = opts.enableAudit !== false;
  if (!auditEnabled) {
    return {
      error:
        "No alert file given and audit was skipped (--skip-audit). Pass a Dependabot JSON file, or omit --skip-audit to run npm/pnpm/yarn audit",
    };
  }

  const client = opts.audit ?? createLiveAudit();
  const result = await client.audit(cwd);
  if (result.error && !result.vulnerabilities.length) {
    return { error: `audit failed: ${result.error}` };
  }
  return { groups: findingsToGroups(filterFindings(result.vulnerabilities, minSeverity)) };
}
