import { loadConfig } from "../config.js";
import {
  alertsFromInput,
  groupAlerts,
  loadAlertFile,
} from "../alerts/dependabot.js";
import { decide } from "../decision/engine.js";
import { analyzeNpmGraph } from "../graph/npm.js";
import { applyFix } from "../fix/apply.js";
import { createLiveRegistry } from "../registry/verify.js";
import { createLiveAudit, filterFindings, findingsToGroups } from "../audit/client.js";
import { nowIso } from "../util/time.js";
import type { AuditClient, CommandResult, PackageAlertGroup, RegistryClient } from "../types.js";

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
  yes?: boolean;
  skipInstall?: boolean;
  registry?: RegistryClient;
  enableAudit?: boolean;
  audit?: AuditClient;
}): Promise<CommandResult> {
  const cwd = opts.cwd;
  const config = loadConfig(cwd);
  const groupsResult = await loadGroups(opts, cwd, config.audit.enabled, config.audit.minSeverity);

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
    return {
      exitCode: 1,
      messages: [
        opts.alertPath
          ? "No package alerts found in input"
          : "Audit found no vulnerabilities at the configured minimum severity",
      ],
      report: {
        title: "analyze: empty",
        generatedAt: nowIso(),
        cwd,
        summary: { groups: 0 },
        entries: [],
      },
    };
  }

  const results: CommandResult[] = [];
  for (const group of groups) {
    const graph = analyzeNpmGraph(cwd, group.package);
    group.installedVersion = graph.versions[0];
    const decision = decide({ graph, advisories: group.advisories, config });
    const registry = opts.registry ?? (opts.apply ? createLiveRegistry() : undefined);
    const result = await applyFix({
      cwd,
      config,
      group,
      graph,
      decision,
      apply: Boolean(opts.apply),
      yes: opts.yes,
      skipInstall: opts.skipInstall ?? true,
      registry,
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
  configAuditEnabled: boolean,
  minSeverity: import("../types.js").Severity,
): Promise<{ groups: PackageAlertGroup[] } | { error: string }> {
  if (opts.alertPath) {
    const raw = loadAlertFile(opts.alertPath);
    return { groups: groupAlerts(alertsFromInput(raw)) };
  }

  const auditEnabled = opts.enableAudit ?? configAuditEnabled;
  if (!auditEnabled) {
    return {
      error: "No alert.json given. Pass a Dependabot file or enable audit in .supplywardenrc.json / --audit",
    };
  }

  const client = opts.audit ?? createLiveAudit();
  const result = await client.audit(cwd);
  if (result.error && !result.vulnerabilities.length) {
    return { error: `audit failed: ${result.error}` };
  }
  return { groups: findingsToGroups(filterFindings(result.vulnerabilities, minSeverity)) };
}
