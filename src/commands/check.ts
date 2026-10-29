import { loadConfig } from "../config.js";
import {
  breakingPinNote,
  breakingUpgradeNote,
  decide,
  formatUpgradeTargets,
  lookupFromRegistry,
  pinLabel,
  rangeRejectionNote,
  safeDirectCopyNote,
  resolveUpgradeDecision,
  stillVulnerable,
  vulnerableReach,
} from "../decision/engine.js";
import { analyzeNpmGraph, resolvePackageManager } from "../graph/npm.js";
import { createLiveAudit, filterFindings, findingsToGroups } from "../audit/client.js";
import { createLiveRegistry } from "../registry/verify.js";
import { groupUpgradeNote, rootUpgradeCommands } from "../fix/upgrade-command.js";
import { extractExistingOverrides, readPackageJson } from "../metadata/sync.js";
import { specFloorSafe, specMinVersion } from "../util/semver-spec.js";
import { advisoryBrief, findingLines, withDirectPatch } from "../report/model.js";
import { nowIso } from "../util/time.js";
import type {
  AuditClient,
  CommandResult,
  Decision,
  Finding,
  GraphAnalysis,
  PackageAlertGroup,
  PackageManager,
  RegistryClient,
  Severity,
  SupplywardenConfig,
} from "../types.js";

export async function runCheck(opts: {
  cwd: string;
  strict?: boolean;
  audit?: AuditClient;
  registry?: RegistryClient;
}): Promise<CommandResult> {
  const cwd = opts.cwd;
  const config = loadConfig(cwd);
  const groups = await loadGroups(opts, cwd, config.audit.minSeverity);
  if ("error" in groups) {
    return {
      exitCode: 1,
      messages: [groups.error],
      report: {
        title: "check",
        generatedAt: nowIso(),
        cwd,
        summary: {},
        entries: [],
      },
    };
  }

  const registry = opts.registry ?? createLiveRegistry(cwd);
  const pins = readPins(cwd);
  const findings: Finding[] = [];
  for (const group of groups.groups) {
    findings.push(await findingFromAudit(cwd, config, group, registry));
  }
  const seen = new Set(findings.map((f) => f.package));
  for (const pin of pins) {
    if (seen.has(pin.package)) continue;
    findings.push(findingForSilentPin(cwd, pin.package, pin.version));
  }

  const actionable = findings.filter((f) => f.action === "upgrade" || f.action === "override");
  const messages = findings.flatMap((f) => findingLines(f));
  if (!findings.length) {
    messages.push(
      "Audit found nothing at the configured minimum severity, and package.json has no overrides.",
    );
  }

  return {
    exitCode: opts.strict && actionable.length ? 1 : 0,
    messages,
    report: {
      title: "check",
      generatedAt: nowIso(),
      cwd,
      summary: {
        findings: findings.length,
        upgrade: findings.filter((f) => f.action === "upgrade").length,
        override: findings.filter((f) => f.action === "override").length,
        keep: findings.filter((f) => f.action === "keep").length,
        drop: findings.filter((f) => f.action === "drop").length,
        wait: findings.filter((f) => f.action === "wait").length,
      },
      entries: findings,
      groups: groups.groups,
    },
  };
}

async function findingFromAudit(
  cwd: string,
  config: SupplywardenConfig,
  group: PackageAlertGroup,
  registry: RegistryClient,
): Promise<Finding> {
  const graph = analyzeNpmGraph(cwd, group.package);
  group.installedVersion = graph.versions[0];
  const decision = await resolveUpgradeDecision(
    decide({ graph, advisories: group.advisories, config }),
    lookupFromRegistry(registry),
    {
      vulnPackage: group.package,
      advisories: group.advisories,
      chains: graph.chains,
      dependencyKind: graph.dependencyKind,
      directs: graph.directs,
      pinDevelopment: config.pinDevelopment,
    },
  );
  return toFinding(cwd, group, graph, decision);
}

function segmentName(segment: string): string {
  const at = segment.lastIndexOf("@");
  return at > 0 ? segment.slice(0, at) : segment;
}

function toFinding(
  cwd: string,
  group: PackageAlertGroup,
  graph: GraphAnalysis,
  decision: Decision,
): Finding {
  const pm = resolvePackageManager(cwd);
  const reach = vulnerableReach(graph, group.advisories);
  const roots = reach.roots.map((r) => `${r.name}@${r.version}`);
  const chains = reach.chains.map((c) => c.path.join(" → "));
  const trails = reach.chains.map((chain) => {
    const path = chain.path.join(" → ");
    const parentSeg = chain.path.length >= 2 ? chain.path[chain.path.length - 2] : undefined;
    const parent = parentSeg ? segmentName(parentSeg) : "";
    const range = parent ? graph.dependers?.find((dep) => dep.parent === parent)?.range : undefined;
    return range ? { path, range } : { path };
  });
  const base: Finding = {
    package: group.package,
    severity: group.maxSeverity,
    advisories: group.advisories,
    installed: graph.versions,
    roots,
    chains,
    trails,
    dependencyKind: graph.dependencyKind,
    action: decision.strategy,
    summary: decision.reason,
    advisory: advisoryBrief(group.advisories) || undefined,
    commands: [],
    forcedVersion: decision.forcedVersion,
    upgradeTargets: decision.upgradeTargets,
  };

  if (decision.strategy === "upgrade") {
    const forced = decision.forcedVersion ?? group.forcedVersion;
    const targets = withDirectPatch(group.package, forced, decision.upgradeTargets ?? []);
    let commands = rootUpgradeCommands(pm, targets).map((c) => c.display);
    if (!commands.length && forced) {
      commands = rootUpgradeCommands(pm, [{ name: group.package, to: forced }]).map(
        (command) => command.display,
      );
    }
    const bump = formatUpgradeTargets({ ...decision, upgradeTargets: targets });
    const noted = { ...decision, upgradeTargets: targets };
    const note = breakingUpgradeNote(noted);
    const together = groupUpgradeNote(targets);
    const rejected = rangeRejectionNote({
      pkg: group.package,
      version: forced ?? "",
      dependers: graph.dependers,
      strategy: "upgrade",
      upgradeTargets: targets,
    });
    const proven = bump ? bump : "No published root version was proven to close the advisory.";
    return {
      ...base,
      summary: [proven, together, rejected, note].filter(Boolean).join(" "),
      commands,
    };
  }

  if (decision.strategy === "wait") {
    return {
      ...base,
      summary: decision.reason,
      commands: [`supplywarden why ${group.package}`],
    };
  }

  const scopes = decision.scopes?.length ? decision.scopes : [decision.scope];

  const forced = decision.forcedVersion ?? group.forcedVersion;
  const pin = readPins(cwd).find((p) => p.package === group.package);
  const pinHolds = Boolean(pin && forced && specFloorSafe(pin.version, group.advisories));
  const lockStillVulnerable = graph.versions.some((v) => stillVulnerable(v, group.advisories));
  const pinNote = forced ? breakingPinNote(group.package, graph.versions, forced) : undefined;
  if (pinHolds && pin) {
    return {
      ...base,
      summary: lockStillVulnerable
        ? `${group.package}@${pin.version} is already pinned in package.json, but the lockfile is still ${graph.versions.join(", ") || "the old version"}.`
        : `${group.package}@${pin.version} is already pinned in package.json.`,
      commands: lockStillVulnerable ? [installCommand(pm)] : [],
    };
  }
  return {
    ...base,
    summary: [
      forced ? pinLabel(group.package, forced, scopes) : decision.reason,
      forced ? safeDirectCopyNote(graph, group.advisories, scopes) : undefined,
      forced
        ? rangeRejectionNote({
            pkg: group.package,
            version: forced,
            dependers: graph.dependers,
            strategy: "override",
          })
        : undefined,
      pinNote,
    ]
      .filter(Boolean)
      .join(" "),
    commands: forced ? [`supplywarden fix ${group.package} --apply`] : [],
  };
}

/** Audit is silent for this pin. Silence usually means the pin is holding the safe version. */
export function findingForSilentPin(cwd: string, pkg: string, version: string): Finding {
  const graph = analyzeNpmGraph(cwd, pkg);
  const roots = graph.roots.map((r) => `${r.name}@${r.version}`);
  const base = {
    package: pkg,
    severity: "unknown" as const,
    advisories: [],
    installed: graph.versions,
    roots,
    chains: graph.chains.map((c) => c.path.join(" → ")),
    dependencyKind: graph.dependencyKind,
    forcedVersion: version,
  };
  if (!graph.inTree) {
    return {
      ...base,
      action: "drop",
      summary: `${pkg} is not in the lockfile. Override ${version} is unused.`,
      commands: [`supplywarden verify ${pkg} --apply`],
    };
  }
  const declared = declaredDepRange(cwd, pkg);
  const declaredFloor = declared ? specMinVersion(declared) : undefined;
  const pinFloor = specMinVersion(version);
  if (declaredFloor && pinFloor && declaredFloor === pinFloor) {
    return {
      ...base,
      action: "drop",
      summary: `package.json already depends on ${pkg}@${declared}. Override ${version} does not change that. It can go.`,
      commands: [`supplywarden verify ${pkg} --apply`],
    };
  }
  const threshold = loadConfig(cwd).upgradeRootThreshold;
  const n = graph.roots.length;
  const installed = graph.versions.join(", ") || version;
  const count =
    n > threshold
      ? `${n} roots, more than the threshold of ${threshold}.`
      : `${n} root(s), at or under the threshold of ${threshold}.`;
  return {
    ...base,
    action: "keep",
    summary: `The audit does not list ${pkg} because ${installed} is installed under override ${version}. ${count} That silence is the pin doing its job, not a reason to remove it. verify ${pkg} is the probe if you want to test the drop.`,
    commands: [`supplywarden verify ${pkg}`],
  };
}

function declaredDepRange(cwd: string, pkgName: string): string | undefined {
  try {
    const pkg = readPackageJson(cwd) as {
      dependencies?: Record<string, string>;
      devDependencies?: Record<string, string>;
      optionalDependencies?: Record<string, string>;
    };
    for (const bag of [pkg.dependencies, pkg.devDependencies, pkg.optionalDependencies]) {
      const range = bag?.[pkgName];
      if (typeof range === "string") return range.replace(/^npm:/, "");
    }
  } catch {
    return undefined;
  }
  return undefined;
}

function installCommand(pm: PackageManager): string {
  if (pm === "pnpm") return "pnpm install";
  if (pm === "yarn") return "yarn install";
  return "npm install";
}

export function readPins(cwd: string): Array<{ package: string; version: string }> {
  try {
    return extractExistingOverrides(readPackageJson(cwd)).map((pin) => ({
      package: pin.package,
      version: pin.version,
    }));
  } catch {
    return [];
  }
}

async function loadGroups(
  opts: { audit?: AuditClient },
  cwd: string,
  minSeverity: Severity,
): Promise<{ groups: PackageAlertGroup[] } | { error: string }> {
  const client = opts.audit ?? createLiveAudit();
  const result = await client.audit(cwd);
  if (result.error && !result.vulnerabilities.length) {
    return { error: `audit failed: ${result.error}` };
  }
  return { groups: findingsToGroups(filterFindings(result.vulnerabilities, minSeverity)) };
}
