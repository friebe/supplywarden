import { loadConfig } from "../config.js";
import { decide, lookupFromRegistry, resolveUpgradeDecision } from "../decision/engine.js";
import { analyzeNpmGraph } from "../graph/npm.js";
import { applyFix } from "../fix/apply.js";
import { createLiveRegistry } from "../registry/verify.js";
import { createLiveInstall } from "../install/client.js";
import { createLiveAudit, filterFindings, findingsToGroups } from "../audit/client.js";
import { findingForSilentPin, readPins } from "./check.js";
import { nowIso } from "../util/time.js";
import type {
  AuditClient,
  CommandResult,
  InstallClient,
  PackageAlertGroup,
  RegistryClient,
} from "../types.js";

export async function runFix(opts: {
  cwd: string;
  /** When set, only this audit package is planned or written. */
  package?: string;
  apply?: boolean;
  skipInstall?: boolean;
  registry?: RegistryClient;
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
        title: "fix: empty",
        generatedAt: nowIso(),
        cwd,
        summary: { groups: 0 },
        entries: [],
      },
    };
  }

  const groups = opts.package
    ? groupsResult.groups.filter((group) => group.package === opts.package)
    : groupsResult.groups;
  if (opts.package && !groups.length) {
    return {
      exitCode: 1,
      messages: [`${opts.package} is not in this audit.`],
      report: {
        title: "fix: empty",
        generatedAt: nowIso(),
        cwd,
        summary: { groups: 0 },
        entries: [],
      },
    };
  }
  if (!groups.length) {
    const pins = readPins(cwd);
    const silent = pins.map((pin) => findingForSilentPin(cwd, pin.package, pin.version));
    const drops = silent.filter((row) => row.action === "drop");
    const hint = pins.length
      ? drops.length
        ? `Audit is clean. ${silent.length - drops.length} pin(s) stay because they are installed. ${drops.length} unused override(s): ${drops.map((row) => row.package).join(", ")}.`
        : `Audit is clean. ${pins.length} pin(s) stay installed, so the silence is the override doing its job.`
      : "Audit found no vulnerabilities at the configured minimum severity";
    return {
      exitCode: pins.length ? 0 : 1,
      messages: [hint],
      report: {
        title: "fix: empty",
        generatedAt: nowIso(),
        cwd,
        summary: { groups: 0, overrides: pins.length },
        entries: [],
      },
    };
  }

  const results: CommandResult[] = [];
  for (const group of groups) {
    const graph = analyzeNpmGraph(cwd, group.package);
    group.installedVersion = graph.versions[0];
    const registry = opts.registry ?? createLiveRegistry(cwd);
    const kind = graph.dependencyKind;
    const decision = await resolveUpgradeDecision(
      decide({ graph, advisories: group.advisories, config }),
      lookupFromRegistry(registry),
      {
        vulnPackage: group.package,
        advisories: group.advisories,
        chains: graph.chains,
        dependencyKind: kind,
        directs: graph.directs,
        pinDevelopment: config.pinDevelopment,
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
    audit?: AuditClient;
  },
  cwd: string,
  minSeverity: import("../types.js").Severity,
): Promise<{ groups: PackageAlertGroup[] } | { error: string }> {
  const client = opts.audit ?? createLiveAudit();
  const result = await client.audit(cwd);
  if (result.error && !result.vulnerabilities.length) {
    return { error: `audit failed: ${result.error}` };
  }
  return { groups: findingsToGroups(filterFindings(result.vulnerabilities, minSeverity)) };
}
