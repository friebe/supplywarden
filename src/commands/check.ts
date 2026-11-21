import { loadConfig } from "../config.js";
import {
  breakingPinNote,
  breakingUpgradeNote,
  decide,
  formatTriageProposal,
  formatUpgradeTargets,
  lookupFromRegistry,
  pinLabel,
  proposeTriageOverride,
  rangeRejectionNote,
  safeDirectCopyNote,
  resolveUpgradeDecision,
  stillVulnerable,
  vulnerableReach,
} from "../decision/engine.js";
import { valid } from "semver";
import { analyzeNpmGraph, resolvePackageManager } from "../graph/npm.js";
import { resolveProjectDir } from "../graph/workspace.js";
import { createLiveAudit, filterFindings, findingsToGroups } from "../audit/client.js";
import { createLiveRegistry } from "../registry/verify.js";
import { advisoryKey, fetchAdvisories } from "../registry/advisories.js";
import {
  groupUpgradeNote,
  lockfileRefreshCommand,
  rootUpgradeCommands,
} from "../fix/upgrade-command.js";
import { extractExistingOverrides, readPackageJson } from "../metadata/sync.js";
import { specFloorSafe, specMinVersion, versionSatisfiesSpec } from "../util/semver-spec.js";
import { advisoryBrief, findingLines, withDirectPatch } from "../report/model.js";
import { judgeParents, planParents } from "../validation/override-need.js";
import { nowIso } from "../util/time.js";
import type {
  Advisory,
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
  const cwd = resolveProjectDir(opts.cwd);
  const config = loadConfig(cwd);
  const audit = opts.audit ?? createLiveAudit();
  const groups = await loadGroups(audit, cwd, config.audit.minSeverity);
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

  const allowAdvisoryLookup = !opts.registry || Boolean(opts.registry.advisoriesFor);
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

  await classifyInstalledOverrides({
    cwd,
    minSeverity: config.audit.minSeverity,
    registry,
    allowAdvisoryLookup,
    findings,
  });

  const actionable = findings.filter(
    (f) =>
      f.action === "refresh" ||
      f.action === "upgrade" ||
      f.action === "override" ||
      f.action === "triage",
  );
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
        refresh: findings.filter((f) => f.action === "refresh").length,
        upgrade: findings.filter((f) => f.action === "upgrade").length,
        override: findings.filter((f) => f.action === "override").length,
        keep: findings.filter((f) => f.action === "keep").length,
        drop: findings.filter((f) => f.action === "drop").length,
        triage: findings.filter((f) => f.action === "triage").length,
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
      dependers: graph.dependers,
      dependencyKind: graph.dependencyKind,
      directs: graph.directs,
      pinDevelopment: config.pinDevelopment,
      threshold: config.upgradeRootThreshold,
    },
  );
  return toFinding(cwd, group, graph, decision);
}

/** Via names the workspace member for a direct dependency, and the member plus the npm root otherwise. */
function displayRoot(
  pkg: string,
  root: { name: string; version: string; importer?: string },
): string {
  if (root.importer && root.name === pkg) return root.importer;
  if (root.importer) return `${root.importer} → ${root.name}@${root.version}`;
  return `${root.name}@${root.version}`;
}

function displayChain(chain: { path: string[]; importer?: string }): string {
  const body = chain.path.join(" → ");
  return chain.importer ? `${chain.importer} → ${body}` : body;
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
  const roots = reach.roots.map((root) => displayRoot(group.package, root));
  const chains = reach.chains.map((chain) => displayChain(chain));
  const trails = reach.chains.map((chain) => {
    const path = displayChain(chain);
    const parentSeg = chain.path.length >= 2 ? chain.path[chain.path.length - 2] : chain.importer;
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
      const pending = decision.upgradeTargets ?? [];
      const filters = [...new Set(pending.map((target) => target.filter).filter(Boolean))];
      const catalogs = [...new Set(pending.map((target) => target.catalog).filter(Boolean))];
      commands = rootUpgradeCommands(pm, [
        {
          name: group.package,
          to: forced,
          ...(filters.length === 1 ? { filter: filters[0] } : {}),
          ...(catalogs.length === 1 ? { catalog: catalogs[0] } : {}),
        },
      ]).map((command) => command.display);
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

  if (decision.strategy === "refresh") {
    return {
      ...base,
      summary: decision.reason,
      commands: [lockfileRefreshCommand(pm, group.package).display],
    };
  }

  if (decision.strategy === "triage") {
    const forced = decision.forcedVersion ?? group.forcedVersion;
    const scopes = decision.scopes?.length ? decision.scopes : [decision.scope];
    const proposal = forced
      ? proposeTriageOverride({
          pkg: group.package,
          version: forced,
          scopes,
          installedVersions: graph.versions,
          advisories: group.advisories,
        })
      : undefined;
    return {
      ...base,
      summary: [decision.reason, proposal ? formatTriageProposal(proposal) : undefined]
        .filter(Boolean)
        .join(" "),
      commands: proposal
        ? [proposal.forceCommand, `supplywarden why ${group.package}`]
        : [`supplywarden why ${group.package}`],
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

/**
 * Audit is silent for this pin. `drop` here is unused (not installed, or already declared).
 * `keep` is only a candidate until the parent ranges are checked against the advisory list.
 */
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
    summary: `The audit does not list ${pkg} because ${installed} is installed under override ${version}. ${count}`,
    commands: [`supplywarden verify ${pkg}`],
  };
}

/**
 * Installed overrides the audit did not list. The lockfile already says which range each
 * parent asked for. That range, not a fresh install, is the version the pin is holding off.
 * One advisory lookup says whether that version is still a problem.
 */
async function classifyInstalledOverrides(opts: {
  cwd: string;
  minSeverity: Severity;
  registry: RegistryClient;
  allowAdvisoryLookup: boolean;
  findings: Finding[];
}): Promise<void> {
  const candidates = opts.findings.filter((finding) => finding.action === "keep");
  if (!candidates.length) return;
  const pins = extractExistingOverrides(readPackageJson(opts.cwd));
  const planned = await Promise.all(
    candidates.map(async (finding) => ({
      finding,
      parents: await planParents({
        pins: pins
          .filter((pin) => pin.package === finding.package)
          .map((pin) => ({ version: pin.version, scope: pin.scope })),
        dependers: analyzeNpmGraph(opts.cwd, finding.package).dependers ?? [],
        resolveRange: (range) => resolveNatural(finding.package, range, opts.registry),
      }),
    })),
  );

  const specs: Array<{ package: string; version: string }> = [];
  for (const row of planned) {
    for (const parent of row.parents ?? []) {
      if (!parent.natural || versionSatisfiesSpec(parent.natural, parent.pin)) continue;
      specs.push({ package: row.finding.package, version: parent.natural });
    }
  }
  const advisories = await loadAdvisories(specs, opts.registry, opts.allowAdvisoryLookup);

  for (const row of planned) {
    const judgment = judgeParents({
      pkg: row.finding.package,
      version: row.finding.forcedVersion ?? "",
      parents: row.parents,
      advisories,
      minSeverity: opts.minSeverity,
    });
    row.finding.action = judgment.action;
    row.finding.summary = judgment.summary;
    row.finding.severity = judgment.severity;
    row.finding.advisories = judgment.advisories;
    row.finding.advisory = advisoryBrief(judgment.advisories) || undefined;
    row.finding.commands =
      judgment.action === "drop"
        ? [`supplywarden verify ${row.finding.package} --apply`]
        : [`supplywarden why ${row.finding.package}`];
  }
}

async function resolveNatural(
  pkg: string,
  range: string,
  registry: RegistryClient,
): Promise<string | undefined> {
  const exact = valid(range);
  if (exact) return exact;
  try {
    return await registry.getLatestMatching?.(pkg, range);
  } catch {
    return undefined;
  }
}

async function loadAdvisories(
  specs: Array<{ package: string; version: string }>,
  registry: RegistryClient,
  allowBulk: boolean,
): Promise<Map<string, Advisory[] | undefined> | null> {
  if (!specs.length) return new Map();
  if (registry.advisoriesFor) {
    const map = new Map<string, Advisory[] | undefined>();
    await Promise.all(
      specs.map(async (spec) => {
        const key = advisoryKey(spec.package, spec.version);
        if (map.has(key)) return;
        map.set(key, undefined);
        try {
          map.set(key, await registry.advisoriesFor!(spec.package, spec.version));
        } catch {
          map.set(key, undefined);
        }
      }),
    );
    return map;
  }
  if (!allowBulk) return null;
  return fetchAdvisories(specs);
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
  audit: AuditClient,
  cwd: string,
  minSeverity: Severity,
): Promise<{ groups: PackageAlertGroup[] } | { error: string }> {
  const result = await audit.audit(cwd);
  if (result.error && !result.vulnerabilities.length) {
    return { error: `audit failed: ${result.error}` };
  }
  return { groups: findingsToGroups(filterFindings(result.vulnerabilities, minSeverity)) };
}
