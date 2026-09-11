import { existsSync, readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import type { MetadataEntry, OverrideScope, SecurityMetadata } from "../types.js";

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

export function syncOverridesToPackageJson(
  cwd: string,
  metadata: SecurityMetadata,
  manifestPath = "package.json",
): { path: string; overrides: Record<string, unknown> } {
  const pkg = readPackageJson(cwd, manifestPath);
  const overrides = buildOverridesObject(metadata.entries);
  if (Object.keys(overrides).length === 0) {
    delete pkg.overrides;
    if (pkg.pnpm) {
      delete pkg.pnpm.overrides;
      if (Object.keys(pkg.pnpm).length === 0) delete pkg.pnpm;
    }
  } else {
    pkg.overrides = overrides;
    pkg.pnpm = { ...(pkg.pnpm ?? {}), overrides };
  }
  const path = writePackageJson(cwd, pkg, manifestPath);
  return { path, overrides };
}

export { overrideValue };
