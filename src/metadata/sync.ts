import { existsSync, readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { detectPackageManager } from "../graph/npm.js";
import type { OverrideScope, PackageManager } from "../types.js";

export type OverridePin = {
  package: string;
  version: string;
  scope: OverrideScope;
  /**
   * When set, writes a version-selector key (`"pkg@${selector}": version`) so older
   * major lines outside the selector stay untouched. Example: `">=7 <11.0.1"`.
   */
  selector?: string;
};

/** Split an override key into package name and optional version selector. */
export function splitOverrideKey(key: string): { package: string; selector?: string } {
  if (key.startsWith("@")) {
    const secondAt = key.indexOf("@", 1);
    if (secondAt === -1) return { package: key };
    return { package: key.slice(0, secondAt), selector: key.slice(secondAt + 1) };
  }
  const at = key.indexOf("@");
  if (at === -1) return { package: key };
  return { package: key.slice(0, at), selector: key.slice(at + 1) };
}

export function overrideKey(pin: Pick<OverridePin, "package" | "selector">): string {
  return pin.selector ? `${pin.package}@${pin.selector}` : pin.package;
}

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
): OverridePin[] {
  if (!overrides) return [];
  const out: OverridePin[] = [];

  for (const [key, value] of Object.entries(overrides)) {
    if (typeof value === "string") {
      const { package: name, selector } = splitOverrideKey(key);
      out.push({
        package: name,
        version: value.replace(/^npm:/, ""),
        scope: { type: "global" },
        ...(selector ? { selector } : {}),
      });
      continue;
    }
    if (value && typeof value === "object") {
      const nested = value as Record<string, unknown>;
      for (const [child, childVal] of Object.entries(nested)) {
        if (child === ".") continue;
        if (typeof childVal === "string") {
          const { package: name, selector } = splitOverrideKey(child);
          out.push({
            package: name,
            version: childVal.replace(/^npm:/, ""),
            scope: { type: "scoped", parent: key },
            ...(selector ? { selector } : {}),
          });
        }
      }
    }
  }
  return out;
}

export function extractExistingOverrides(pkg: PackageJson): OverridePin[] {
  const npm = flattenOverrides(pkg.overrides);
  const pnpm = flattenOverrides(pkg.pnpm?.overrides);
  const yarn = Object.entries(pkg.resolutions ?? {}).map(([key, version]): OverridePin => {
    const parts = key.split("/");
    if (parts.length >= 2 && !key.startsWith("@")) {
      const child = splitOverrideKey(parts.slice(1).join("/"));
      return {
        package: child.package,
        version,
        scope: { type: "scoped" as const, parent: parts[0]! },
        ...(child.selector ? { selector: child.selector } : {}),
      };
    }
    const global = splitOverrideKey(key);
    return {
      package: global.package,
      version,
      scope: { type: "global" as const },
      ...(global.selector ? { selector: global.selector } : {}),
    };
  });
  const seen = new Set<string>();
  return [...npm, ...pnpm, ...yarn].filter((item) => {
    const parent = item.scope.type === "scoped" ? item.scope.parent : "";
    const key = `${overrideKey(item)}@${item.version}:${item.scope.type}:${parent}`;
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });
}

export function buildOverridesObject(entries: OverridePin[]): Record<string, unknown> {
  const result: Record<string, unknown> = {};
  for (const entry of entries) {
    const key = overrideKey(entry);
    if (entry.scope.type === "scoped") {
      const parent = entry.scope.parent;
      const existing = result[parent];
      if (existing && typeof existing === "object") {
        (existing as Record<string, string>)[key] = entry.version;
      } else if (typeof existing === "undefined") {
        result[parent] = { [key]: entry.version };
      } else {
        result[key] = entry.version;
      }
    } else {
      result[key] = entry.version;
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
    else pkg.pnpm = { ...pkg.pnpm, overrides };
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

export function writeOverrides(
  cwd: string,
  entries: OverridePin[],
  manifestPath = "package.json",
): { path: string; overrides: Record<string, unknown> } {
  const pkg = readPackageJson(cwd, manifestPath);
  const overrides = buildOverridesObject(entries);
  const pm = detectPackageManager(cwd);
  writeOverrideSyntax(pkg, pm, overrides);
  const path = writePackageJson(cwd, pkg, manifestPath);
  return { path, overrides };
}

export function upsertOverride(
  cwd: string,
  pin: OverridePin,
  manifestPath = "package.json",
): { path: string; overrides: Record<string, unknown> } {
  const pkg = readPackageJson(cwd, manifestPath);
  const parent = pin.scope.type === "scoped" ? pin.scope.parent : "";
  const kept = extractExistingOverrides(pkg).filter((item) => {
    const itemParent = item.scope.type === "scoped" ? item.scope.parent : "";
    // A forced selector pin replaces any prior global pin for the same package
    // (plain or selector). Scoped pins still match on parent.
    if (pin.scope.type === "global" && item.scope.type === "global") {
      return item.package !== pin.package;
    }
    return !(
      item.package === pin.package &&
      item.scope.type === pin.scope.type &&
      itemParent === parent &&
      (item.selector ?? "") === (pin.selector ?? "")
    );
  });
  return writeOverrides(cwd, [...kept, pin], manifestPath);
}

function deletePackageKeys(bag: Record<string, unknown>, packageName: string): void {
  for (const key of Object.keys(bag)) {
    const value = bag[key];
    if (splitOverrideKey(key).package === packageName) {
      delete bag[key];
      continue;
    }
    if (value && typeof value === "object") {
      const nested = value as Record<string, unknown>;
      for (const child of Object.keys(nested)) {
        if (splitOverrideKey(child).package === packageName) delete nested[child];
      }
      if (Object.keys(nested).length === 0) delete bag[key];
    }
  }
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
    if (!bag) continue;
    deletePackageKeys(bag, packageName);
  }
  if (pkg.overrides && Object.keys(pkg.overrides).length === 0) delete pkg.overrides;
  if (pkg.pnpm?.overrides && Object.keys(pkg.pnpm.overrides).length === 0) {
    delete pkg.pnpm.overrides;
    if (Object.keys(pkg.pnpm).length === 0) delete pkg.pnpm;
  }
  if (pkg.resolutions && Object.keys(pkg.resolutions).length === 0) delete pkg.resolutions;
  writePackageJson(cwd, pkg, manifestPath);
}
