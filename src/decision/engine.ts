import { major, satisfies, valid, gt } from "semver";
import type { Advisory, Decision, GraphAnalysis, OverrideScope, SupplywardenConfig } from "../types.js";
import { inferSafeFloorFromVulnerableRange } from "../util/vuln-range.js";

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

export function formatUpgradeTarget(t: { name: string; from?: string; to?: string }): string {
  if (t.to && t.from && t.to !== t.from) return `${t.name}@${t.from} → ${t.to}`;
  if (t.to) return `${t.name} → ${t.to}`;
  if (t.from) return `${t.name} (installed ${t.from}; need a newer release)`;
  return t.name;
}

export async function resolveUpgradeDecision(
  decision: Decision,
  lookup: {
    latestVersion?: (pkg: string) => Promise<string | undefined>;
    getLatestMatching?: (pkg: string, range: string) => Promise<string | undefined>;
  } = {},
): Promise<Decision> {
  if (decision.strategy !== "upgrade" || !decision.upgradeTargets?.length) return decision;
  if (!lookup.latestVersion && !lookup.getLatestMatching) return decision;

  let knownAll = true;
  const targets = [];
  for (const t of decision.upgradeTargets) {
    const from = t.from && valid(t.from) ? t.from : undefined;
    const sameMajorRange =
      from !== undefined ? `>${from} <${major(from) + 1}.0.0` : undefined;
    const latestSameMajor = sameMajorRange
      ? await lookup.getLatestMatching?.(t.name, sameMajorRange)
      : undefined;
    const latestOverall =
      (await lookup.latestVersion?.(t.name)) ?? (await lookup.getLatestMatching?.(t.name, "*"));
    if (latestOverall === undefined && latestSameMajor === undefined) knownAll = false;
    targets.push({ ...t, to: upgradeTargetTo(from, latestSameMajor, latestOverall) });
  }

  if (targets.every((t) => !t.to) && knownAll && decision.forcedVersion) {
    const installed = targets.map((t) => `${t.name}@${t.from ?? "?"}`).join(", ");
    return {
      strategy: "override",
      reason: `${installed} already at latest published version; root upgrade cannot go higher — override ${decision.forcedVersion}`,
      forcedVersion: decision.forcedVersion,
      scope: decision.scope,
    };
  }

  return { ...decision, upgradeTargets: targets };
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
