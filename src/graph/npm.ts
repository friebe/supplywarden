import { existsSync, readFileSync } from "node:fs";
import { join } from "node:path";
import type { DependencyChain, DependencyKind, GraphAnalysis, PackageManager, RootPackage } from "../types.js";

type LockPackage = {
  version?: string;
  name?: string;
  dependencies?: Record<string, string>;
  optionalDependencies?: Record<string, string>;
  devDependencies?: Record<string, string>;
  dev?: boolean;
  optional?: boolean;
  devOptional?: boolean;
};

type NpmLockfile = {
  lockfileVersion?: number;
  packages?: Record<string, LockPackage>;
};

function loadLockfile(cwd: string): NpmLockfile | null {
  const path = join(cwd, "package-lock.json");
  if (!existsSync(path)) return null;
  return JSON.parse(readFileSync(path, "utf8")) as NpmLockfile;
}

function nodeName(lockPath: string): string {
  if (lockPath === "") return "";
  const parts = lockPath.split("node_modules/");
  return parts[parts.length - 1] ?? lockPath;
}

function parentPath(lockPath: string): string | null {
  if (!lockPath.includes("node_modules/")) return null;
  const idx = lockPath.lastIndexOf("/node_modules/");
  if (idx >= 0) return lockPath.slice(0, idx);
  if (lockPath.startsWith("node_modules/")) return "";
  return null;
}

function allDeps(meta: LockPackage | undefined): Record<string, string> {
  if (!meta) return {};
  return {
    ...(meta.dependencies ?? {}),
    ...(meta.optionalDependencies ?? {}),
    ...(meta.devDependencies ?? {}),
  };
}

export function analyzeNpmGraph(cwd: string, pkgName: string): GraphAnalysis {
  const lock = loadLockfile(cwd);
  if (!lock?.packages) {
    return { package: pkgName, versions: [], inTree: false, roots: [], chains: [], dependerRanges: [] };
  }

  const packages = lock.packages;
  const root = packages[""] ?? {};
  const directDeps = allDeps(root);

  const matches = Object.entries(packages).filter(([p, meta]) => {
    if (p === "") return false;
    return nodeName(p) === pkgName || meta.name === pkgName;
  });

  const versions = [...new Set(matches.map(([, m]) => m.version).filter(Boolean))] as string[];
  const dependerRanges = [
    ...new Set(
      Object.values(packages)
        .map((meta) => allDeps(meta)[pkgName])
        .filter((range): range is string => Boolean(range)),
    ),
  ];
  const chains: DependencyChain[] = [];
  const rootMap = new Map<string, RootPackage>();

  const dependents = Object.entries(packages).filter(
    ([, meta]) => pkgName in allDeps(meta),
  );

  for (const [lockPath, meta] of matches) {
    const nestedChain: string[] = [];
    let current: string | null = lockPath;
    while (current && current !== "") {
      nestedChain.unshift(`${nodeName(current)}@${packages[current]?.version ?? "?"}`);
      current = parentPath(current);
    }

    if (nestedChain.length > 1) {
      chains.push({ path: nestedChain, package: pkgName, version: meta.version ?? "?" });
      const topName = stripAtVersion(nestedChain[0]!);
      if (topName in directDeps) {
        rootMap.set(topName, {
          name: topName,
          version: packages[`node_modules/${topName}`]?.version ?? "?",
          range: directDeps[topName],
        });
      }
    } else {
      for (const [depPath] of dependents) {
        if (depPath === "") {
          rootMap.set(pkgName, {
            name: pkgName,
            version: meta.version ?? "?",
            range: directDeps[pkgName],
          });
          chains.push({
            path: [`${pkgName}@${meta.version ?? "?"}`],
            package: pkgName,
            version: meta.version ?? "?",
          });
          continue;
        }
        const depName = nodeName(depPath);
        const chain = [`${depName}@${packages[depPath]?.version ?? "?"}`, `${pkgName}@${meta.version ?? "?"}`];
        chains.push({ path: chain, package: pkgName, version: meta.version ?? "?" });
        if (depName in directDeps) {
          rootMap.set(depName, {
            name: depName,
            version: packages[depPath]?.version ?? "?",
            range: directDeps[depName],
          });
        } else {
          const top = findRoot(packages, depPath, directDeps);
          if (top) rootMap.set(top.name, top);
        }
      }
    }
  }

  if (chains.length === 0 && matches.length) {
    chains.push({
      path: [`${pkgName}@${matches[0]![1].version ?? "?"}`],
      package: pkgName,
      version: matches[0]![1].version ?? "?",
    });
  }

  const roots = [...rootMap.values()];
  return {
    package: pkgName,
    versions,
    inTree: matches.length > 0,
    roots,
    chains,
    dependerRanges,
    dependencyKind: matches.length
      ? inferDependencyKind({
          pkgName,
          copies: matches.map(([, meta]) => meta),
          rootNames: roots.map((r) => r.name),
          rootDependencies: root.dependencies,
          rootDevDependencies: root.devDependencies,
          rootOptionalDependencies: root.optionalDependencies,
        })
      : undefined,
  };
}

type LockFlags = {
  dev?: boolean;
  optional?: boolean;
  devOptional?: boolean;
};

export function inferDependencyKind(opts: {
  pkgName: string;
  copies: LockFlags[];
  rootNames: string[];
  rootDependencies?: Record<string, string>;
  rootDevDependencies?: Record<string, string>;
  rootOptionalDependencies?: Record<string, string>;
}): DependencyKind {
  const prod = opts.rootDependencies ?? {};
  const dev = opts.rootDevDependencies ?? {};
  const opt = opts.rootOptionalDependencies ?? {};
  const inProd = (name: string) => name in prod;
  const inDev = (name: string) => name in dev;
  const inOpt = (name: string) => name in opt;

  if (inProd(opts.pkgName) || opts.rootNames.some(inProd)) return "production";

  if (opts.copies.length) {
    const allDev = opts.copies.every((c) => c.dev === true);
    const allOpt = opts.copies.every((c) => c.optional === true || c.devOptional === true);
    const anyUnflagged = opts.copies.some((c) => !c.dev && !c.optional && !c.devOptional);
    if (allDev) return "development";
    if (allOpt) return "optional";
    if (anyUnflagged && (opts.rootNames.length === 0 || opts.rootNames.some(inProd))) {
      return "production";
    }
  }

  if (opts.rootNames.length > 0 && opts.rootNames.every(inOpt) && !opts.rootNames.some(inProd)) {
    return "optional";
  }
  if (inDev(opts.pkgName) || (opts.rootNames.length > 0 && opts.rootNames.every(inDev))) {
    return "development";
  }
  if (inOpt(opts.pkgName)) return "optional";
  return "production";
}

export function dependencyKindLabel(kind?: DependencyKind): string {
  if (kind === "development" || kind === "optional") return kind;
  return "";
}

export function mergeDependencyKind(a?: DependencyKind, b?: DependencyKind): DependencyKind | undefined {
  if (!a) return b;
  if (!b) return a;
  if (a === "production" || b === "production") return "production";
  if (a === b) return a;
  return "production";
}

function stripAtVersion(segment: string): string {
  const at = segment.lastIndexOf("@");
  if (at <= 0) return segment;
  return segment.slice(0, at);
}

function findRoot(
  packages: Record<string, LockPackage>,
  lockPath: string,
  directDeps: Record<string, string>,
): RootPackage | undefined {
  let current: string | null = lockPath;
  while (current && current !== "") {
    const name = nodeName(current);
    if (name in directDeps) {
      return {
        name,
        version: packages[current]?.version ?? packages[`node_modules/${name}`]?.version ?? "?",
        range: directDeps[name],
      };
    }
    current = parentPath(current);
  }
  const name = nodeName(lockPath);
  if (name in directDeps) {
    return { name, version: packages[lockPath]?.version ?? "?", range: directDeps[name] };
  }
  return undefined;
}

export function resolvedVersion(cwd: string, pkgName: string): string | undefined {
  return analyzeNpmGraph(cwd, pkgName).versions[0];
}

export function detectPackageManager(cwd: string): PackageManager | "unknown" {
  const fromField = packageManagerFromManifest(cwd);
  if (fromField) return fromField;
  if (existsSync(join(cwd, "pnpm-lock.yaml"))) return "pnpm";
  if (existsSync(join(cwd, "yarn.lock"))) return "yarn";
  if (existsSync(join(cwd, "package-lock.json"))) return "npm";
  return "unknown";
}

/** Lockfile/manifest PM, or npm if none is detected. */
export function resolvePackageManager(cwd: string): PackageManager {
  const detected = detectPackageManager(cwd);
  return detected === "unknown" ? "npm" : detected;
}

function packageManagerFromManifest(cwd: string): "npm" | "pnpm" | "yarn" | undefined {
  const path = join(cwd, "package.json");
  if (!existsSync(path)) return undefined;
  try {
    const pkg = JSON.parse(readFileSync(path, "utf8")) as { packageManager?: unknown };
    const raw = String(pkg.packageManager ?? "").trim().toLowerCase();
    const name = raw.split("@")[0];
    if (name === "npm" || name === "pnpm" || name === "yarn") return name;
  } catch {
    return undefined;
  }
  return undefined;
}

export function hasLockfile(cwd: string): boolean {
  return detectPackageManager(cwd) !== "unknown";
}
