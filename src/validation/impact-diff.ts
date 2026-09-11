import type { ImpactDiff, SupplywardenConfig } from "../types.js";

export function assessImpact(changedPackages: number, config: SupplywardenConfig): ImpactDiff {
  return {
    changedPackages,
    warning: changedPackages >= config.impactWarnThreshold,
    blocked: changedPackages >= config.impactBlockThreshold,
  };
}

/** Estimate lockfile impact from chain count when a full dry-run is unavailable. */
export function estimateImpact(chainCount: number, rootCount: number): number {
  return Math.max(chainCount, rootCount, 1);
}
