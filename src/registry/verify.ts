import { execPmSync } from "../util/pm-exec.js";
import { maxSatisfying, valid } from "semver";

export type NpmPackument = {
  "dist-tags"?: { latest?: string };
  versions?: Record<string, { deprecated?: string }>;
  time?: Record<string, string>;
};

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

export function createLiveRegistry() {
  return {
    async verifyPackageVersion(pkg: string, version: string) {
      const packument = await fetchPackument(pkg);
      if (!packument?.versions) return { exists: false, deprecated: null };
      const meta = packument.versions[version];
      if (!meta) return { exists: false, deprecated: null };
      return { exists: true, deprecated: meta.deprecated ?? null };
    },
    async latestVersion(pkg: string) {
      const packument = await fetchPackument(pkg);
      if (!packument) return undefined;
      return latestFromPackument(packument);
    },
    async getLatestMatching(pkg: string, range: string) {
      const packument = await fetchPackument(pkg);
      if (!packument) return undefined;
      return matchingFromPackument(packument, range);
    },
  };
}

export function createOfflineRegistry(known: Record<string, string[]> = {}) {
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
