import { compare, major, minVersion, satisfies, valid, gt } from "semver";
import type {
  Advisory,
  Decision,
  DependencyChain,
  DependencyKind,
  Depender,
  GraphAnalysis,
  OverrideScope,
  RootPackage,
  RegistryClient,
  Severity,
  Strategy,
  SupplywardenConfig,
  UpgradeTarget,
} from "../types.js";
import { inferSafeFloorFromVulnerableRange } from "../util/vuln-range.js";

export type UpgradeLookup = {
  latestVersion?: (pkg: string) => Promise<string | undefined>;
  getLatestMatching?: (pkg: string, range: string) => Promise<string | undefined>;
  versionsNewerThan?: (pkg: string, from: string) => Promise<string[] | undefined>;
  dependencyRange?: (pkg: string, version: string, dep: string) => Promise<string | undefined>;
  minMatching?: (pkg: string, range: string) => Promise<string | undefined>;
  peerDependencies?: (pkg: string, version: string) => Promise<Record<string, string> | undefined>;
};

export type UpgradeProofContext = {
  vulnPackage: string;
  advisories: Advisory[];
  chains: DependencyChain[];
  dependencyKind?: DependencyKind;
  directs?: Array<{ name: string; version: string }>;
  /** When false, a non-critical dev or optional tree waits instead of pinning. Default: pin. */
  pinDevelopment?: boolean;
};

export function recommend(input: {
  rootCount: number;
  threshold: number;
  canUpgradeRoots: boolean;
  kind?: DependencyKind;
  severity?: Severity;
  pinDevelopment?: boolean;
}): Strategy {
  if (input.canUpgradeRoots && input.rootCount <= input.threshold) return "upgrade";
  if (shouldWait(input.kind, input.severity, input.pinDevelopment !== false)) return "wait";
  return "override";
}

/** Dev/optional trees wait only when `pinDevelopment` is off, and never for a critical advisory. */
export function shouldWait(
  kind?: DependencyKind,
  severity?: Severity,
  pinDevelopment = true,
): boolean {
  if (pinDevelopment) return false;
  if (severity === "critical") return false;
  return kind === "development" || kind === "optional";
}

function maxAdvisorySeverity(advisories: Advisory[]): Severity {
  let best: Severity = "unknown";
  const rank: Record<Severity, number> = { critical: 4, high: 3, medium: 2, low: 1, unknown: 0 };
  for (const advisory of advisories) {
    if (rank[advisory.severity] > rank[best]) best = advisory.severity;
  }
  return best;
}

export function decide(opts: {
  graph: GraphAnalysis;
  advisories: Advisory[];
  config: SupplywardenConfig;
}): Decision {
  const forcedVersion = firstSafeForcedVersion(opts.advisories);
  const rootCount = opts.graph.roots.length || 1;
  const kind = opts.graph.dependencyKind;
  const severity = maxAdvisorySeverity(opts.advisories);
  const canUpgrade = Boolean(forcedVersion) && rootCount <= opts.config.upgradeRootThreshold;
  const strategy = recommend({
    rootCount,
    threshold: opts.config.upgradeRootThreshold,
    canUpgradeRoots: canUpgrade,
    kind,
    severity,
    pinDevelopment: opts.config.pinDevelopment,
  });

  const scopes = overrideScopes(opts.graph, opts.advisories);
  const scope = scopes[0] ?? { type: "global" as const };

  const threshold = opts.config.upgradeRootThreshold;
  const tree =
    kind === "development" || kind === "optional" ? `${kind} dependency` : "production dependency";

  if (strategy === "upgrade") {
    return {
      strategy: "upgrade",
      reason: `${rootCount} root(s), at or under the threshold of ${threshold}. Upgrade the root before pinning.`,
      forcedVersion,
      scope,
      scopes,
      upgradeTargets: opts.graph.roots.map((r) => ({
        name: r.name,
        from: r.version,
        ...(r.importer ? { filter: r.importer } : {}),
        ...(r.catalog ? { catalog: r.catalog } : {}),
      })),
    };
  }

  if (strategy === "wait") {
    const count =
      rootCount > threshold
        ? `${rootCount} roots, more than the threshold of ${threshold}.`
        : `${rootCount} root(s).`;
    const patch = forcedVersion ? "" : " The advisory names no patched version.";
    return {
      strategy: "wait",
      reason: `${count} This is a ${tree}, severity ${severity}, not critical.${patch} No root upgrade and no pin.`,
      forcedVersion,
      scope,
      scopes,
    };
  }

  const why = !forcedVersion
    ? "The advisory names no patched version, so there is nothing safe to pin."
    : rootCount > threshold
      ? `${rootCount} roots, more than the threshold of ${threshold}. A root upgrade is not attempted.`
      : `${rootCount} root(s), at or under the threshold of ${threshold}, and a root upgrade is not available.`;
  return {
    strategy: "override",
    reason: forcedVersion ? `${why} ${pinLabel(opts.graph.package, forcedVersion, scopes)}` : why,
    forcedVersion,
    scope,
    scopes,
  };
}

export function formatUpgradeTarget(t: {
  name: string;
  from?: string;
  to?: string;
  skipped?: string[];
}): string {
  const skip = formatSkipped(t.skipped);
  if (t.to && t.from && t.to !== t.from) return `${t.name}@${t.from} → ${t.to}${skip}`;
  if (t.to) return `${t.name} → ${t.to}${skip}`;
  if (t.from) return `${t.name} (installed ${t.from}; need a newer release)`;
  return t.name;
}

function formatSkipped(skipped?: string[]): string {
  if (!skipped?.length) return "";
  const shown = skipped.slice(0, 3);
  const more = skipped.length > shown.length ? ` +${skipped.length - shown.length}` : "";
  return ` (not ${shown.join(", ")}${more} — still vulnerable)`;
}

/** `from → to` when the two versions are different majors, otherwise undefined. */
export function majorJumpLabel(from?: string, to?: string): string | undefined {
  if (!from || !to || !valid(from) || !valid(to)) return undefined;
  if (major(from) === major(to)) return undefined;
  return `${from} → ${to}`;
}

/** Proven root upgrades that cross a major, e.g. `express@4.18.2 → 5.0.0`. */
export function breakingUpgradeSummary(decision?: Decision): string {
  if (!decision?.upgradeTargets?.length) return "";
  return decision.upgradeTargets
    .map((t) => {
      const jump = t.to ? majorJumpLabel(t.from, t.to) : undefined;
      return jump ? `${t.name}@${jump}` : undefined;
    })
    .filter((label): label is string => Boolean(label))
    .join(", ");
}

export function breakingUpgradeNote(decision?: Decision): string | undefined {
  const summary = breakingUpgradeSummary(decision);
  if (!summary) return undefined;
  return `No override written. The advisory only closes with a breaking major upgrade: ${summary}. package.json was left unchanged.`;
}

function majorPinLabels(
  pkg: string,
  installed: string[],
  forced: string,
  direction: "up" | "down",
): string {
  return installed
    .filter((version) => {
      if (!majorJumpLabel(version, forced)) return false;
      const fromMajor = major(version);
      const toMajor = major(forced);
      return direction === "up" ? fromMajor < toMajor : fromMajor > toMajor;
    })
    .map((version) => `${pkg}@${version} → ${forced}`)
    .join(", ");
}

/** Installed copies the pin would move onto another major. */
export function breakingPinSummary(pkg: string, installed: string[], forced?: string): string {
  if (!forced) return "";
  return [
    majorPinLabels(pkg, installed, forced, "up"),
    majorPinLabels(pkg, installed, forced, "down"),
  ]
    .filter(Boolean)
    .join(", ");
}

export function breakingPinNote(
  pkg: string,
  installed: string[],
  forced?: string,
): string | undefined {
  if (!forced) return undefined;
  const up = majorPinLabels(pkg, installed, forced, "up");
  const down = majorPinLabels(pkg, installed, forced, "down");
  const notes: string[] = [];
  if (up) notes.push(`Breaking major pin: ${up}. Dependents still on the old major can break.`);
  if (down) notes.push(`Breaking major pin: ${down}. Forcing an older major can break.`);
  return notes.join(" ") || undefined;
}

/** Lowest proven root version(s) that close the advisory, e.g. `nx@23.2.1 → 23.2.5`. */
export function formatUpgradeTargets(decision?: Decision): string {
  if (decision?.strategy !== "upgrade") return "";
  return (decision.upgradeTargets ?? [])
    .filter((t) => Boolean(t.to))
    .map(formatUpgradeTarget)
    .join(", ");
}

export function lookupFromRegistry(registry?: RegistryClient): UpgradeLookup {
  if (!registry) return {};
  return {
    latestVersion: registry.latestVersion?.bind(registry),
    getLatestMatching: registry.getLatestMatching?.bind(registry),
    versionsNewerThan: registry.versionsNewerThan?.bind(registry),
    dependencyRange: registry.dependencyRange?.bind(registry),
    minMatching: registry.minMatching?.bind(registry),
    peerDependencies: registry.peerDependencies?.bind(registry),
  };
}

export async function resolveUpgradeDecision(
  decision: Decision,
  lookup: UpgradeLookup = {},
  proof?: UpgradeProofContext,
): Promise<Decision> {
  if (decision.strategy === "wait") return decision;
  if (decision.strategy !== "upgrade" || !decision.upgradeTargets?.length) return decision;
  if (!hasLookup(lookup)) return decision;

  let lookedUpAny = false;
  let hadCandidate = false;
  const targets: NonNullable<Decision["upgradeTargets"]> = [];
  for (const t of decision.upgradeTargets) {
    const from = t.from && valid(t.from) ? t.from : undefined;
    const { versions, lookedUp } = await candidateVersions(t.name, from, lookup);
    if (lookedUp) lookedUpAny = true;
    if (versions.length) hadCandidate = true;
    let to: string | undefined;
    const skipped: string[] = [];
    if (proof) {
      for (const version of preferSameMajor(from, versions)) {
        if (await rootVersionClosesVuln(t.name, version, proof, lookup)) {
          to = version;
          break;
        }
        skipped.push(version);
      }
    }
    targets.push({ ...t, to, skipped: skipped.length ? skipped : undefined });
  }

  if (targets.every((t) => Boolean(t.to)) && proof) {
    return withPeerCompanions(
      { ...decision, upgradeTargets: targets },
      proof.directs ?? [],
      lookup,
    );
  }

  if (lookedUpAny && decision.forcedVersion) {
    const installed = targets.map((t) => `${t.name}@${t.from ?? "?"}`).join(", ");
    const kind = proof?.dependencyKind;
    const severity = proof ? maxAdvisorySeverity(proof.advisories) : undefined;
    if (shouldWait(kind, severity, proof?.pinDevelopment !== false)) {
      return {
        strategy: "wait",
        reason: `${installed} has no published version that closes ${proof?.vulnPackage ?? "the advisory"}. ${kind ?? "non-production"} dependency, not critical — no pin.`,
        forcedVersion: decision.forcedVersion,
        scope: decision.scope,
        scopes: decision.scopes,
      };
    }
    const pin = pinLabel(
      proof?.vulnPackage ?? "it",
      decision.forcedVersion,
      decision.scopes ?? [decision.scope],
    );
    const reason = hadCandidate
      ? `${installed} has no published version that closes ${proof?.vulnPackage ?? "the advisory"}. ${pin}`
      : `${installed} is already the latest published version, so a root upgrade cannot go higher. ${pin}`;
    return {
      strategy: "override",
      reason,
      forcedVersion: decision.forcedVersion,
      scope: decision.scope,
      scopes: decision.scopes,
    };
  }

  return { ...decision, upgradeTargets: targets };
}

function hasLookup(lookup: UpgradeLookup): boolean {
  return Boolean(
    lookup.latestVersion ||
    lookup.getLatestMatching ||
    lookup.versionsNewerThan ||
    lookup.dependencyRange,
  );
}

async function candidateVersions(
  name: string,
  from: string | undefined,
  lookup: UpgradeLookup,
): Promise<{ versions: string[]; lookedUp: boolean }> {
  if (from && lookup.versionsNewerThan) {
    const raw = await lookup.versionsNewerThan(name, from);
    if (raw === undefined) return { versions: [], lookedUp: false };
    const versions = raw.filter((version) => valid(version) && gt(version, from));
    return { versions, lookedUp: true };
  }

  const sameMajorRange = from !== undefined ? `>${from} <${major(from) + 1}.0.0` : undefined;
  const latestSameMajor = sameMajorRange
    ? await lookup.getLatestMatching?.(name, sameMajorRange)
    : undefined;
  const latestOverall =
    (await lookup.latestVersion?.(name)) ?? (await lookup.getLatestMatching?.(name, "*"));
  const lookedUp = latestSameMajor !== undefined || latestOverall !== undefined;
  const versions = uniqueNewer(from, [latestSameMajor, latestOverall]);
  return { versions, lookedUp };
}

function uniqueNewer(from: string | undefined, raw: Array<string | undefined>): string[] {
  const out: string[] = [];
  for (const version of raw) {
    if (!version || !valid(version)) continue;
    if (from && valid(from) && !gt(version, from)) continue;
    if (!out.includes(version)) out.push(version);
  }
  return out;
}

function preferSameMajor(from: string | undefined, versions: string[]): string[] {
  const same: string[] = [];
  const other: string[] = [];
  for (const version of versions) {
    if (from && valid(from) && valid(version) && major(version) === major(from)) same.push(version);
    else other.push(version);
  }
  same.sort(compare);
  other.sort(compare);
  return [...same, ...other];
}

async function rootVersionClosesVuln(
  rootName: string,
  rootVersion: string,
  proof: UpgradeProofContext,
  lookup: UpgradeLookup,
): Promise<boolean> {
  if (rootName === proof.vulnPackage) {
    return !stillVulnerable(rootVersion, proof.advisories);
  }

  const chains = proof.chains.filter((chain) => stripVersion(chain.path[0] ?? "") === rootName);
  const namesList = chains.length
    ? chains.map((chain) => chain.path.map(stripVersion))
    : [[rootName, proof.vulnPackage]];

  for (const names of namesList) {
    if (!(await chainCloses(rootName, rootVersion, names, proof, lookup))) return false;
  }
  return namesList.length > 0;
}

async function chainCloses(
  rootName: string,
  rootVersion: string,
  names: string[],
  proof: UpgradeProofContext,
  lookup: UpgradeLookup,
): Promise<boolean> {
  const rootIdx = names.indexOf(rootName);
  const vulnIdx = names.lastIndexOf(proof.vulnPackage);
  if (rootIdx < 0 || vulnIdx <= rootIdx) return false;

  let pkg = rootName;
  let version = rootVersion;
  for (let i = rootIdx + 1; i <= vulnIdx; i++) {
    const next = names[i]!;
    const range = await lookup.dependencyRange?.(pkg, version, next);
    if (!range) return false;
    if (i === vulnIdx) return rangeFloorSafe(range, proof.advisories);
    const hop = (await lookup.minMatching?.(next, range)) ?? rangeMinVersion(range);
    if (!hop || !valid(hop)) return false;
    pkg = next;
    version = hop;
  }
  return false;
}

function rangeFloorSafe(spec: string, advisories: Advisory[]): boolean {
  const min = rangeMinVersion(spec);
  return Boolean(min && !stillVulnerable(min, advisories));
}

function rangeMinVersion(spec: string): string | undefined {
  try {
    return minVersion(spec.replace(/^npm:/, "").trim())?.version;
  } catch {
    return undefined;
  }
}

function copyStillVulnerable(version: string | undefined, advisories?: Advisory[]): boolean {
  if (!advisories) return true;
  if (!version || version === "?") return true;
  return stillVulnerable(version, advisories);
}

/** Roots and chains whose installed copy is still inside the advisory. A safe copy stays out of Via. */
export function vulnerableReach(
  graph: GraphAnalysis,
  advisories: Advisory[],
): { roots: RootPackage[]; chains: DependencyChain[] } {
  const chains = graph.chains.filter((chain) => stillVulnerable(chain.version, advisories));
  if (!chains.length) return { roots: graph.roots, chains: graph.chains };
  const names = new Set(
    chains.map((chain) => stripVersion(chain.path[0] ?? "")).filter((name) => name.length > 0),
  );
  const roots = graph.roots.filter((root) => names.has(root.name));
  return { roots: roots.length ? roots : graph.roots, chains };
}

/** One scoped pin per parent that still pulls a vulnerable copy. A vulnerable direct dependency stays a global pin. */
export function overrideScopes(graph: GraphAnalysis, advisories?: Advisory[]): OverrideScope[] {
  const parents = new Set<string>();
  let directVulnerable = graph.roots.some(
    (root) => root.name === graph.package && copyStillVulnerable(root.version, advisories),
  );
  for (const chain of graph.chains) {
    const names = chain.path.map((segment) => stripVersion(segment));
    const idx = names.lastIndexOf(graph.package);
    if (idx <= 0) {
      if (copyStillVulnerable(chain.version, advisories)) directVulnerable = true;
      continue;
    }
    if (!copyStillVulnerable(chain.version, advisories)) continue;
    const parent = names[idx - 1];
    if (parent) parents.add(parent);
  }
  if (directVulnerable || parents.size === 0) return [{ type: "global" }];
  return [...parents].sort().map((parent) => ({ type: "scoped", parent }));
}

/** The installed direct copy is already outside the advisory, so the pin must not move it. */
export function safeDirectCopyNote(
  graph: GraphAnalysis,
  advisories: Advisory[],
  scopes: OverrideScope[],
): string | undefined {
  if (scopes.some((scope) => scope.type === "global")) return undefined;
  const version = graph.roots.find((root) => root.name === graph.package)?.version;
  if (!version || version === "?" || stillVulnerable(version, advisories)) return undefined;
  return `${graph.package}@${version} is already outside the advisory.`;
}

export function pinLabel(pkg: string, version: string, scopes: OverrideScope[]): string {
  const parents = scopes.flatMap((scope) => (scope.type === "scoped" ? [scope.parent] : []));
  if (!parents.length) return `Pin ${pkg}@${version}.`;
  return `Pin ${pkg}@${version} under ${parents.join(" and ")}.`;
}

async function withPeerCompanions(
  decision: Decision,
  directs: Array<{ name: string; version: string }>,
  lookup: UpgradeLookup,
): Promise<Decision> {
  if (!lookup.peerDependencies) return decision;
  const targets = [...(decision.upgradeTargets ?? [])];
  const have = new Set(targets.map((target) => target.name));
  const additions: NonNullable<Decision["upgradeTargets"]> = [];
  for (const target of targets) {
    if (!target.to) continue;
    const publishedPeers = (await lookup.peerDependencies(target.name, target.to)) ?? {};
    for (const dep of directs) {
      if (have.has(dep.name) || !dep.version || dep.version === "?" || dep.name === target.name) {
        continue;
      }
      const installedPeers = await lookup.peerDependencies(dep.name, dep.version);
      const installedRange = installedPeers?.[target.name];
      const rejectsTarget = Boolean(installedRange && !rangeAccepts(installedRange, target.to));
      const requiredRange = publishedPeers[dep.name];
      const targetRejectsInstalled = Boolean(
        requiredRange && !rangeAccepts(requiredRange, dep.version),
      );
      if (!rejectsTarget && !targetRejectsInstalled) continue;
      const to = await companionVersion(dep.name, target.to, requiredRange, lookup);
      if (!to || to === dep.version) continue;
      additions.push({
        name: dep.name,
        from: dep.version,
        to,
        ...(target.filter ? { filter: target.filter } : {}),
      });
      have.add(dep.name);
    }
  }
  if (!additions.length) return decision;
  return { ...decision, upgradeTargets: [...targets, ...additions] };
}

async function companionVersion(
  name: string,
  preferred: string,
  requiredRange: string | undefined,
  lookup: UpgradeLookup,
): Promise<string | undefined> {
  const atPreferred = await lookup.peerDependencies?.(name, preferred);
  if (atPreferred && (!requiredRange || rangeAccepts(requiredRange, preferred))) return preferred;
  if (requiredRange) return lookup.minMatching?.(name, requiredRange);
  return undefined;
}

function rangeAccepts(range: string, version: string): boolean {
  try {
    return satisfies(version, range, { includePrerelease: true });
  } catch {
    return false;
  }
}

/** Installed parents whose range does not accept `version`. */
export function rejectedBy(dependers: Depender[] | undefined, version: string): Depender[] {
  if (!dependers?.length || !valid(version)) return [];
  const seen = new Set<string>();
  const out: Depender[] = [];
  for (const depender of dependers) {
    const key = `${depender.parent}\0${depender.range}`;
    if (seen.has(key)) continue;
    seen.add(key);
    if (rangeAccepts(depender.range, version)) continue;
    out.push(depender);
  }
  return out.sort((a, b) => a.parent.localeCompare(b.parent));
}

/**
 * One sentence when a naive bump of `pkg` lands outside a parent's range.
 * A proven root upgrade is named as the step that moves that range.
 */
export function rangeRejectionNote(opts: {
  pkg: string;
  version: string;
  dependers?: Depender[];
  strategy: "upgrade" | "override";
  upgradeTargets?: UpgradeTarget[];
}): string | undefined {
  const rejected = rejectedBy(opts.dependers, opts.version);
  if (!rejected.length) return undefined;
  const asking = formatAsking(opts.pkg, rejected);
  const outside = `${asking}. That does not include ${opts.version}.`;
  if (opts.strategy === "upgrade") {
    const moved = (opts.upgradeTargets ?? [])
      .filter((target) => target.to)
      .map((target) =>
        target.from
          ? `${target.name}@${target.from} → ${target.to}`
          : `${target.name}@${target.to}`,
      )
      .join(", ");
    if (!moved) return outside;
    return `${outside} Upgrade the root first. ${moved} moves that range.`;
  }
  const parent = rejected.length === 1 ? "That parent can" : "Those parents can";
  return `${outside} The pin forces ${opts.pkg}@${opts.version}. ${parent} fail to build.`;
}

function formatAsking(pkg: string, rejected: Depender[]): string {
  const byRange = new Map<string, string[]>();
  for (const depender of rejected) {
    const label = depender.version ? `${depender.parent}@${depender.version}` : depender.parent;
    const list = byRange.get(depender.range) ?? [];
    list.push(label);
    byRange.set(depender.range, list);
  }
  return [...byRange.entries()]
    .map(([range, parents]) => {
      const verb = parents.length > 1 ? "ask" : "asks";
      return `${parents.join(" and ")} ${verb} for ${pkg}@${range}`;
    })
    .join("; ");
}

function stripVersion(segment: string): string {
  const at = segment.lastIndexOf("@");
  if (at <= 0) return segment;
  return segment.slice(0, at);
}

/** Version that sits outside every advisory range — not merely the `patchedVersion` field. */
export function firstSafeForcedVersion(advisories: Advisory[]): string | undefined {
  const floors: string[] = [];
  for (const advisory of advisories) {
    if (
      advisory.patchedVersion &&
      valid(advisory.patchedVersion) &&
      !stillVulnerable(advisory.patchedVersion, [advisory])
    ) {
      floors.push(advisory.patchedVersion);
      continue;
    }
    const inferred = inferSafeFloorFromVulnerableRange(advisory.vulnerableRange);
    if (inferred) floors.push(inferred);
  }
  if (!floors.length) return undefined;
  let best = floors[0]!;
  for (const floor of floors.slice(1)) {
    if (gt(floor, best)) best = floor;
  }
  return stillVulnerable(best, advisories) ? undefined : best;
}

export function stillVulnerable(version: string, advisories: Advisory[]): boolean {
  if (!valid(version)) return true;
  return advisories.some((a) => {
    try {
      return satisfies(version, a.vulnerableRange, { includePrerelease: true });
    } catch {
      return false;
    }
  });
}
