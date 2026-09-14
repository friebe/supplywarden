import { gte, minVersion, satisfies, valid } from "semver";
import { stillVulnerable } from "../decision/engine.js";
import type { Advisory } from "../types.js";

function cleanSpec(spec: string): string {
  return spec.replace(/^npm:/, "").trim();
}

/** Lowest version a dependency/override spec can resolve to (`^6.11.2` → `6.11.2`). */
export function specMinVersion(spec: string): string | undefined {
  try {
    return minVersion(cleanSpec(spec))?.version;
  } catch {
    return undefined;
  }
}

export function versionSatisfiesSpec(version: string, spec: string): boolean {
  if (version === spec) return true;
  try {
    return satisfies(version, cleanSpec(spec), { includePrerelease: true });
  } catch {
    return false;
  }
}

/** True when the spec's floor is already outside every advisory's vulnerable range. */
export function specFloorSafe(spec: string, advisories: Advisory[]): boolean {
  const min = specMinVersion(spec);
  if (!min) return false;
  return !stillVulnerable(min, advisories);
}

/** True when spec's floor is >= baseline (exact version or another spec). */
export function specAtLeast(spec: string, baseline: string): boolean {
  const min = specMinVersion(spec);
  const base = specMinVersion(baseline) ?? (valid(baseline) ? baseline : undefined);
  if (!min || !base) return spec === baseline;
  return gte(min, base);
}
