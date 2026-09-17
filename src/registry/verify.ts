import { existsSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { execPmSync } from "../util/pm-exec.js";
import { compare, gt, maxSatisfying, minSatisfying, valid } from "semver";

/** Optional cwd stubs so a kitchen-sink lockfile is not overwritten by live npm packuments. */
export const REGISTRY_OVERLAY_FILENAME = "supplywarden.registry.json";

export type NpmPackumentVersion = {
  deprecated?: string;
  dependencies?: Record<string, string>;
  optionalDependencies?: Record<string, string>;
};

export type NpmPackument = {
  "dist-tags"?: { latest?: string };
  versions?: Record<string, NpmPackumentVersion>;
  time?: Record<string, string>;
};

/** pkg → version → dep → range */
export type OfflineDepTree = Record<string, Record<string, Record<string, string>>>;

export async function fetchPackument(pkg: string): Promise<NpmPackument | null> {
  const url = `https://registry.npmjs.org/${encodeURIComponent(pkg)}`;
  try {
    const res = await fetch(url, { headers: { Accept: "application/json" } });
    if (!res.ok) return null;
    return (await res.json()) as NpmPackument;
  } catch {
    return null;
  }
}

function publishedVersions(packument: NpmPackument): string[] {
  return Object.entries(packument.versions ?? {})
    .filter(([, meta]) => !meta?.deprecated)
    .map(([version]) => version)
    .filter((version) => Boolean(valid(version)));
}

export function latestFromPackument(packument: NpmPackument): string | undefined {
  const tag = packument["dist-tags"]?.latest;
  if (tag && valid(tag) && !packument.versions?.[tag]?.deprecated) return tag;
  return maxSatisfying(publishedVersions(packument), "*") ?? undefined;
}

export function matchingFromPackument(packument: NpmPackument, range: string): string | undefined {
  return maxSatisfying(publishedVersions(packument), range) ?? undefined;
}

export function minMatchingFromPackument(packument: NpmPackument, range: string): string | undefined {
  return minSatisfying(publishedVersions(packument), range) ?? undefined;
}

export function versionsNewerThanFromPackument(packument: NpmPackument, from: string): string[] {
  if (!valid(from)) return [];
  const allowPrerelease = from.includes("-");
  return publishedVersions(packument)
    .filter((version) => gt(version, from) && (allowPrerelease || !version.includes("-")))
    .sort(compare);
}

export function dependencyRangeFromPackument(
  packument: NpmPackument,
  version: string,
  dep: string,
): string | undefined {
  const meta = packument.versions?.[version];
  if (!meta) return undefined;
  return meta.dependencies?.[dep] ?? meta.optionalDependencies?.[dep];
}

export function loadRegistryOverlay(cwd: string): OfflineDepTree {
  const path = join(cwd, REGISTRY_OVERLAY_FILENAME);
  if (!existsSync(path)) return {};
  try {
    const raw = JSON.parse(readFileSync(path, "utf8")) as unknown;
    if (!raw || typeof raw !== "object" || Array.isArray(raw)) return {};
    return raw as OfflineDepTree;
  } catch {
    return {};
  }
}

function overlayVersions(deps: Record<string, Record<string, string>> | undefined): string[] {
  return Object.keys(deps ?? {}).filter((version) => Boolean(valid(version)));
}

export function createLiveRegistry(cwd?: string) {
  const overlay = cwd ? loadRegistryOverlay(cwd) : {};
  const cache = new Map<string, Promise<NpmPackument | null>>();
  const packumentOf = (pkg: string): Promise<NpmPackument | null> => {
    let hit = cache.get(pkg);
    if (!hit) {
      hit = fetchPackument(pkg);
      cache.set(pkg, hit);
    }
    return hit;
  };

  return {
    async verifyPackageVersion(pkg: string, version: string) {
      const stub = overlay[pkg];
      if (stub) return { exists: version in stub, deprecated: null };
      const packument = await packumentOf(pkg);
      if (!packument?.versions) return { exists: false, deprecated: null };
      const meta = packument.versions[version];
      if (!meta) return { exists: false, deprecated: null };
      return { exists: true, deprecated: meta.deprecated ?? null };
    },
    async latestVersion(pkg: string) {
      const stub = overlay[pkg];
      if (stub) return maxSatisfying(overlayVersions(stub), "*") ?? undefined;
      const packument = await packumentOf(pkg);
      if (!packument) return undefined;
      return latestFromPackument(packument);
    },
    async getLatestMatching(pkg: string, range: string) {
      const stub = overlay[pkg];
      if (stub) return maxSatisfying(overlayVersions(stub), range) ?? undefined;
      const packument = await packumentOf(pkg);
      if (!packument) return undefined;
      return matchingFromPackument(packument, range);
    },
    async versionsNewerThan(pkg: string, from: string) {
      const stub = overlay[pkg];
      if (stub) {
        if (!valid(from)) return [];
        const allowPrerelease = from.includes("-");
        return overlayVersions(stub)
          .filter((version) => gt(version, from) && (allowPrerelease || !version.includes("-")))
          .sort(compare);
      }
      const packument = await packumentOf(pkg);
      if (!packument) return undefined;
      return versionsNewerThanFromPackument(packument, from);
    },
    async dependencyRange(pkg: string, version: string, dep: string) {
      const stub = overlay[pkg];
      if (stub) return stub[version]?.[dep];
      const packument = await packumentOf(pkg);
      if (!packument) return undefined;
      return dependencyRangeFromPackument(packument, version, dep);
    },
    async minMatching(pkg: string, range: string) {
      const stub = overlay[pkg];
      if (stub) return minSatisfying(overlayVersions(stub), range) ?? undefined;
      const packument = await packumentOf(pkg);
      if (!packument) return undefined;
      return minMatchingFromPackument(packument, range);
    },
  };
}

export function createOfflineRegistry(
  known: Record<string, string[]> = {},
  deps: OfflineDepTree = {},
) {
  return {
    async verifyPackageVersion(pkg: string, version: string) {
      const versions = known[pkg];
      if (!versions) return { exists: true, deprecated: null };
      return { exists: versions.includes(version), deprecated: null };
    },
    async latestVersion(pkg: string) {
      const versions = known[pkg];
      if (!versions) return undefined;
      return maxSatisfying(versions, "*") ?? undefined;
    },
    async getLatestMatching(pkg: string, range: string) {
      const versions = known[pkg];
      if (!versions) return undefined;
      return maxSatisfying(versions, range) ?? undefined;
    },
    async versionsNewerThan(pkg: string, from: string) {
      const versions = known[pkg];
      if (!versions) return undefined;
      if (!valid(from)) return [];
      const allowPrerelease = from.includes("-");
      return versions
        .filter((version) => valid(version) && gt(version, from) && (allowPrerelease || !version.includes("-")))
        .sort(compare);
    },
    async dependencyRange(pkg: string, version: string, dep: string) {
      return deps[pkg]?.[version]?.[dep];
    },
    async minMatching(pkg: string, range: string) {
      const versions = known[pkg];
      if (!versions) return undefined;
      return minSatisfying(versions, range) ?? undefined;
    },
  };
}

export function npmVersion(): string | null {
  try {
    return execPmSync("npm", ["--version"], { timeout: 15_000 });
  } catch {
    return null;
  }
}

export function pnpmVersion(): string | null {
  try {
    return execPmSync("pnpm", ["--version"], { timeout: 15_000 });
  } catch {
    return null;
  }
}

export function parseNpmMajor(version: string): number {
  const major = Number(version.split(".")[0]);
  return Number.isFinite(major) ? major : 0;
}

export type MaintenanceScore = "well-maintained" | "stale" | "abandoned" | "unknown";

export function scoreMaintenance(packument: NpmPackument | null): MaintenanceScore {
  if (!packument?.time) return "unknown";
  const modified = packument.time.modified ?? packument.time.created;
  if (!modified) return "unknown";
  const ageDays = (Date.now() - new Date(modified).getTime()) / 86_400_000;
  if (ageDays < 180) return "well-maintained";
  if (ageDays < 730) return "stale";
  return "abandoned";
}
