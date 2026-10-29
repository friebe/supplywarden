import { existsSync, readdirSync, readFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { parse as parseYaml } from "yaml";

export type Catalogs = {
  default: Record<string, string>;
  named: Record<string, Record<string, string>>;
};

/** Directory that holds `pnpm-workspace.yaml` and the lockfile. A nested project with its own lockfile stays put. */
export function findPnpmRoot(start: string): string | undefined {
  let dir = resolve(start);
  if (existsSync(join(dir, "pnpm-lock.yaml"))) return dir;
  if (hasOtherLock(dir)) return undefined;
  for (;;) {
    const parent = dirname(dir);
    if (parent === dir) return undefined;
    dir = parent;
    if (existsSync(join(dir, "pnpm-lock.yaml")) && existsSync(join(dir, "pnpm-workspace.yaml"))) {
      return dir;
    }
    if (hasOtherLock(dir)) return undefined;
  }
}

/** Workspace root when `start` is a member; otherwise `start`. */
export function resolveProjectDir(cwd: string): string {
  return findPnpmRoot(cwd) ?? cwd;
}

export function readCatalogs(root: string): Catalogs {
  const path = join(root, "pnpm-workspace.yaml");
  if (!existsSync(path)) return { default: {}, named: {} };
  try {
    const doc = parseYaml(readFileSync(path, "utf8")) as {
      catalog?: Record<string, unknown>;
      catalogs?: Record<string, Record<string, unknown>>;
    };
    const named: Record<string, Record<string, string>> = {};
    for (const [name, bag] of Object.entries(doc.catalogs ?? {})) {
      named[name] = stringBag(bag);
    }
    return { default: stringBag(doc.catalog), named };
  } catch {
    return { default: {}, named: {} };
  }
}

/** `catalog:` is the default catalog. `catalog:react18` is a named one. */
export function catalogSpec(
  catalogs: Catalogs,
  specifier: string,
  pkg: string,
): { name: string; range: string } | undefined {
  if (specifier === "catalog:") {
    return { name: "default", range: catalogs.default[pkg] ?? "" };
  }
  if (specifier.startsWith("catalog:")) {
    const name = specifier.slice("catalog:".length);
    return { name, range: catalogs.named[name]?.[pkg] ?? "" };
  }
  return undefined;
}

export function isWorkspaceSpecifier(specifier: string, versionField: string): boolean {
  return (
    specifier.startsWith("workspace:") ||
    specifier.startsWith("link:") ||
    versionField.startsWith("link:")
  );
}

/** Package name used by `pnpm --filter`. The workspace root (`.`) has no filter. */
export function importerPackageName(root: string, importerKey: string): string | undefined {
  if (!importerKey || importerKey === ".") return undefined;
  const pkgPath = join(root, importerKey, "package.json");
  try {
    const name = JSON.parse(readFileSync(pkgPath, "utf8")).name;
    if (typeof name === "string" && name.trim()) return name.trim();
  } catch {
    // directory name below
  }
  return importerKey.split("/").filter(Boolean).pop();
}

/** Member `package.json` paths relative to the workspace root, plus `pnpm-workspace.yaml`. */
export function extraSnapshotFiles(cwd: string): string[] {
  const root = findPnpmRoot(cwd) ?? cwd;
  if (!existsSync(join(root, "pnpm-workspace.yaml"))) return [];
  return ["pnpm-workspace.yaml", ...workspaceMemberManifests(root)];
}

function workspaceMemberManifests(root: string): string[] {
  const out: string[] = [];
  const seen = new Set<string>();
  const add = (rel: string) => {
    const norm = rel.split("\\").join("/");
    if (norm === "package.json" || seen.has(norm)) return;
    if (!existsSync(join(root, norm))) return;
    seen.add(norm);
    out.push(norm);
  };
  for (const pattern of readPackagePatterns(root)) {
    if (!pattern || pattern === ".") continue;
    const star = pattern.indexOf("*");
    if (star < 0) {
      add(`${pattern.replace(/\/$/, "")}/package.json`);
      continue;
    }
    // One trailing segment: `apps/*`, `packages/*`. Nested `**` is left alone.
    if (pattern.slice(star) !== "*" || pattern.includes("**")) continue;
    const dir = pattern.slice(0, star).replace(/\/$/, "");
    if (!dir) continue;
    const base = join(root, dir);
    if (!existsSync(base)) continue;
    for (const entry of readdirSync(base, { withFileTypes: true })) {
      if (!entry.isDirectory() || entry.name.startsWith(".")) continue;
      add(`${dir}/${entry.name}/package.json`);
    }
  }
  return out;
}

function readPackagePatterns(root: string): string[] {
  try {
    const doc = parseYaml(readFileSync(join(root, "pnpm-workspace.yaml"), "utf8")) as {
      packages?: unknown;
    };
    if (!Array.isArray(doc.packages)) return [];
    return doc.packages.filter((entry): entry is string => typeof entry === "string");
  } catch {
    return [];
  }
}

function stringBag(bag: Record<string, unknown> | undefined): Record<string, string> {
  const out: Record<string, string> = {};
  if (!bag) return out;
  for (const [key, value] of Object.entries(bag)) {
    if (typeof value === "string") out[key] = value;
  }
  return out;
}

function hasOtherLock(dir: string): boolean {
  return existsSync(join(dir, "package-lock.json")) || existsSync(join(dir, "yarn.lock"));
}
