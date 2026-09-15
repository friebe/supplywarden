import { satisfies, valid, gt } from "semver";
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
