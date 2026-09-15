import { gte, inc } from "semver";

/**
 * First version that sits outside a vulnerable range.
 * `< 4.0.8` → `4.0.8`; `<=4.0.7` → `4.0.8`; `>=4.0.0 <4.0.8 || <2.3.2` → `4.0.8`.
 */
export function inferSafeFloorFromVulnerableRange(range?: string): string | undefined {
  if (!range || range === "*") return undefined;
  let best: string | undefined;
  const re = /(<=|<)\s*(\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?)/g;
  for (const match of range.matchAll(re)) {
    const exclusive = match[1] === "<";
    const bound = match[2]!;
    const floor = exclusive ? bound : (inc(bound, "patch") ?? bound);
    if (!best || gte(floor, best)) best = floor;
  }
  return best;
}
