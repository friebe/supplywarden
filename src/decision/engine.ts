import { compare, major, minVersion, satisfies, valid, gt } from "semver";
import type {
  Advisory,
  Decision,
  DependencyChain,
  GraphAnalysis,
  OverrideScope,
  RegistryClient,
  SupplywardenConfig,
} from "../types.js";
import { inferSafeFloorFromVulnerableRange } from "../util/vuln-range.js";

export type UpgradeLookup = {
  latestVersion?: (pkg: string) => Promise<string | undefined>;
  getLatestMatching?: (pkg: string, range: string) => Promise<string | undefined>;
  versionsNewerThan?: (pkg: string, from: string) => Promise<string[] | undefined>;
  dependencyRange?: (pkg: string, version: string, dep: string) => Promise<string | undefined>;
  minMatching?: (pkg: string, range: string) => Promise<string | undefined>;
};

export type UpgradeProofContext = {
  vulnPackage: string;
  advisories: Advisory[];
  chains: DependencyChain[];
};

export function recommend(input: {
  rootCount: number;
  threshold: number;
  canUpgradeRoots: boolean;
}): "upgrade" | "override" {
  if (input.canUpgradeRoots && input.rootCount <= input.threshold) return "upgrade";
  return "override";
}

export function decide(opts: {
  graph: GraphAnalysis;
  advisories: Advisory[];
  config: SupplywardenConfig;
}): Decision {
  const forcedVersion = firstSafeForcedVersion(opts.advisories);
  const rootCount = opts.graph.roots.length || 1;
  const canUpgrade = Boolean(forcedVersion) && rootCount <= opts.config.upgradeRootThreshold;
  const strategy = recommend({
    rootCount,
    threshold: opts.config.upgradeRootThreshold,
    canUpgradeRoots: canUpgrade,
  });

  const scope: OverrideScope =
    opts.graph.chains.length === 1 && opts.graph.roots[0] && opts.graph.roots[0].name !== opts.graph.package
      ? { type: "scoped", parent: parentFromChain(opts.graph.chains[0]!.path, opts.graph.package) ?? opts.graph.roots[0].name }
      : { type: "global" };

  if (strategy === "upgrade") {
    return {
      strategy: "upgrade",
      reason: `${rootCount} root package(s) affected (≤ threshold ${opts.config.upgradeRootThreshold}); prefer a semver-safe root upgrade`,
      forcedVersion,
      scope,
      upgradeTargets: opts.graph.roots.map((r) => ({ name: r.name, from: r.version })),
    };
  }

  return {
    strategy: "override",
    reason: `${rootCount} root package(s) affected${rootCount > opts.config.upgradeRootThreshold ? ` (> threshold ${opts.config.upgradeRootThreshold})` : ""}; override ${forcedVersion ?? "?"} closes ${opts.advisories.length} advisory(ies)`,
    forcedVersion,
    scope,
  };
}

/** Newer than `from`. Prefers the same major, then overall latest. */
export function upgradeTargetTo(
  from: string | undefined,
  latestSameMajor: string | undefined,
  latestOverall?: string | undefined,
): string | undefined {
  const pick = (candidate: string | undefined): string | undefined => {
    if (!candidate || !valid(candidate)) return undefined;
    if (!from || !valid(from)) return candidate;
    return gt(candidate, from) ? candidate : undefined;
  };
  return pick(latestSameMajor) ?? pick(latestOverall);
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
  };
}

export async function resolveUpgradeDecision(
  decision: Decision,
  lookup: UpgradeLookup = {},
  proof?: UpgradeProofContext,
): Promise<Decision> {
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
    return { ...decision, upgradeTargets: targets };
  }

  if (lookedUpAny && decision.forcedVersion) {
    const installed = targets.map((t) => `${t.name}@${t.from ?? "?"}`).join(", ");
    const reason = hadCandidate
      ? `${installed} has no proven version that closes ${proof?.vulnPackage ?? "the advisory"} — override ${decision.forcedVersion}`
      : `${installed} already at latest published version; root upgrade cannot go higher — override ${decision.forcedVersion}`;
    return {
      strategy: "override",
      reason,
      forcedVersion: decision.forcedVersion,
      scope: decision.scope,
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

function parentFromChain(path: string[], pkg: string): string | undefined {
  const names = path.map((p) => p.replace(/@[^@]+$/, "").replace(/^@/, "@"));
  const idx = names.findIndex((n) => n === pkg || n.endsWith(`/${pkg}`) || n === pkg);
  if (idx > 0) return stripVersion(path[idx - 1]!);
  if (path.length >= 2) return stripVersion(path[path.length - 2]!);
  return undefined;
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
