import { existsSync, readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { detectPackageManager } from "../graph/npm.js";
import type { MetadataEntry, OverrideScope, PackageManager, SecurityMetadata } from "../types.js";

type PackageJson = {
  overrides?: Record<string, unknown>;
  pnpm?: { overrides?: Record<string, unknown> };
  resolutions?: Record<string, string>;
  [key: string]: unknown;
};

export function readPackageJson(cwd: string, manifestPath = "package.json"): PackageJson {
  const path = join(cwd, manifestPath);
  if (!existsSync(path)) {
    throw new Error(`package.json not found at ${path}`);
  }
  return JSON.parse(readFileSync(path, "utf8")) as PackageJson;
}

export function writePackageJson(
  cwd: string,
  pkg: PackageJson,
  manifestPath = "package.json",
): string {
  const path = join(cwd, manifestPath);
  writeFileSync(path, `${JSON.stringify(pkg, null, 2)}\n`);
  return path;
}

export function flattenOverrides(
  overrides: Record<string, unknown> | undefined,
): Array<{ package: string; version: string; scope: OverrideScope }> {
  if (!overrides) return [];
  const out: Array<{ package: string; version: string; scope: OverrideScope }> = [];

  for (const [key, value] of Object.entries(overrides)) {
    if (typeof value === "string") {
      out.push({ package: key, version: value.replace(/^npm:/, ""), scope: { type: "global" } });
      continue;
    }
    if (value && typeof value === "object") {
      const nested = value as Record<string, unknown>;
      for (const [child, childVal] of Object.entries(nested)) {
        if (child === ".") continue;
        if (typeof childVal === "string") {
          out.push({
            package: child,
            version: childVal.replace(/^npm:/, ""),
            scope: { type: "scoped", parent: key },
          });
        }
      }
    }
  }
  return out;
}

export function extractExistingOverrides(pkg: PackageJson) {
  const npm = flattenOverrides(pkg.overrides);
  const pnpm = flattenOverrides(pkg.pnpm?.overrides);
  const yarn = Object.entries(pkg.resolutions ?? {}).map(([key, version]) => {
    const parts = key.split("/");
    if (parts.length >= 2 && !key.startsWith("@")) {
      return {
        package: parts.slice(1).join("/"),
        version,
        scope: { type: "scoped" as const, parent: parts[0]! },
      };
    }
    return {
      package: key,
      version,
      scope: { type: "global" as const },
    };
  });
  const seen = new Set<string>();
  return [...npm, ...pnpm, ...yarn].filter((item) => {
    const parent = item.scope.type === "scoped" ? item.scope.parent : "";
    const key = `${item.package}@${item.version}:${item.scope.type}:${parent}`;
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });
}

function overrideValue(entry: MetadataEntry): unknown {
  if (entry.scope.type === "scoped") {
    return { [entry.scope.parent]: { [entry.package]: entry.forcedVersion } };
  }
  return entry.forcedVersion;
}

export function buildOverridesObject(entries: MetadataEntry[]): Record<string, unknown> {
  const result: Record<string, unknown> = {};
  for (const entry of entries.filter((e) => e.status === "active" || e.status === "pending_verify")) {
    if (entry.scope.type === "scoped") {
      const parent = entry.scope.parent;
      const existing = result[parent];
      if (existing && typeof existing === "object") {
        (existing as Record<string, string>)[entry.package] = entry.forcedVersion;
      } else if (typeof existing === "undefined") {
        result[parent] = { [entry.package]: entry.forcedVersion };
      } else {
        result[entry.package] = entry.forcedVersion;
      }
    } else {
      result[entry.package] = entry.forcedVersion;
    }
  }
  return result;
}

function toYarnResolutions(overrides: Record<string, unknown>): Record<string, string> {
  const out: Record<string, string> = {};
  for (const [key, value] of Object.entries(overrides)) {
    if (typeof value === "string") {
      out[key] = value;
      continue;
    }
    if (value && typeof value === "object") {
      for (const [child, ver] of Object.entries(value as Record<string, unknown>)) {
        if (typeof ver === "string") out[`${key}/${child}`] = ver;
      }
    }
  }
  return out;
}

function clearPnpmOverrides(pkg: PackageJson): void {
  if (!pkg.pnpm) return;
  delete pkg.pnpm.overrides;
  if (Object.keys(pkg.pnpm).length === 0) delete pkg.pnpm;
}

function writeOverrideSyntax(
  pkg: PackageJson,
  pm: PackageManager | "unknown",
  overrides: Record<string, unknown>,
): void {
  const empty = Object.keys(overrides).length === 0;
  if (pm === "pnpm") {
    delete pkg.overrides;
    if (empty) clearPnpmOverrides(pkg);
    else pkg.pnpm = { ...(pkg.pnpm ?? {}), overrides };
    if (pkg.resolutions && Object.keys(pkg.resolutions).length === 0) delete pkg.resolutions;
    return;
  }
  if (pm === "yarn") {
    delete pkg.overrides;
    clearPnpmOverrides(pkg);
    if (empty) delete pkg.resolutions;
    else pkg.resolutions = toYarnResolutions(overrides);
    return;
  }
  clearPnpmOverrides(pkg);
  if (empty) delete pkg.overrides;
  else pkg.overrides = overrides;
}

export function syncOverridesToPackageJson(
  cwd: string,
  metadata: SecurityMetadata,
  manifestPath = "package.json",
): { path: string; overrides: Record<string, unknown> } {
  const pkg = readPackageJson(cwd, manifestPath);
  const overrides = buildOverridesObject(metadata.entries);
  const pm = detectPackageManager(cwd);
  writeOverrideSyntax(pkg, pm, overrides);
  const path = writePackageJson(cwd, pkg, manifestPath);
  return { path, overrides };
}

export function deleteOverrideFromManifest(
  cwd: string,
  packageName: string,
  manifestPath = "package.json",
): void {
  const pkg = readPackageJson(cwd, manifestPath);
  const bags: Array<Record<string, unknown> | undefined> = [
    pkg.overrides,
    pkg.pnpm?.overrides as Record<string, unknown> | undefined,
    pkg.resolutions as Record<string, unknown> | undefined,
  ];
  for (const bag of bags) {
    if (!bag || !(packageName in bag)) continue;
    delete bag[packageName];
  }
  if (pkg.overrides && Object.keys(pkg.overrides).length === 0) delete pkg.overrides;
  if (pkg.pnpm?.overrides && Object.keys(pkg.pnpm.overrides).length === 0) {
    delete pkg.pnpm.overrides;
    if (Object.keys(pkg.pnpm).length === 0) delete pkg.pnpm;
  }
  if (pkg.resolutions && Object.keys(pkg.resolutions).length === 0) delete pkg.resolutions;
  writePackageJson(cwd, pkg, manifestPath);
}

export { overrideValue };
