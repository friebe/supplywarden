import { execFileSync } from "node:child_process";

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

export function createLiveRegistry() {
  return {
    async verifyPackageVersion(pkg: string, version: string) {
      const packument = await fetchPackument(pkg);
      if (!packument?.versions) return { exists: false, deprecated: null };
      const meta = packument.versions[version];
      if (!meta) return { exists: false, deprecated: null };
      return { exists: true, deprecated: meta.deprecated ?? null };
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
  };
}

export function npmVersion(): string | null {
  try {
    return execFileSync("npm", ["--version"], { encoding: "utf8" }).trim();
  } catch {
    return null;
  }
}

export function pnpmVersion(): string | null {
  try {
    return execFileSync("pnpm", ["--version"], { encoding: "utf8" }).trim();
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
