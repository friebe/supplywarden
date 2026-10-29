import { existsSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { parseAllDocuments } from "yaml";
import type { GraphAnalysis } from "../types.js";
import { analyzeFlatGraph, emptyGraph, type DirectDep, type FlatNode } from "./flat.js";
import {
  catalogSpec,
  findPnpmRoot,
  importerPackageName,
  isWorkspaceSpecifier,
  readCatalogs,
  type Catalogs,
} from "./workspace.js";

type PnpmImporterBag = Record<string, { specifier?: string; version?: string } | string>;

type PnpmImporter = {
  dependencies?: PnpmImporterBag;
  devDependencies?: PnpmImporterBag;
  optionalDependencies?: PnpmImporterBag;
};

type PnpmPackage = {
  dependencies?: Record<string, string>;
  optionalDependencies?: Record<string, string>;
  peerDependencies?: Record<string, string>;
};

type PnpmLock = {
  lockfileVersion?: string | number;
  importers?: Record<string, PnpmImporter>;
  packages?: Record<string, PnpmPackage>;
  snapshots?: Record<string, PnpmPackage>;
  dependencies?: PnpmImporterBag;
  devDependencies?: PnpmImporterBag;
  optionalDependencies?: PnpmImporterBag;
};

export function pnpmLockPath(cwd: string): string {
  return join(cwd, "pnpm-lock.yaml");
}

export function hasPnpmLock(cwd: string): boolean {
  const root = findPnpmRoot(cwd);
  return Boolean(root && existsSync(pnpmLockPath(root)));
}

export function analyzePnpmGraph(cwd: string, pkgName: string): GraphAnalysis {
  const root = findPnpmRoot(cwd) ?? cwd;
  const path = pnpmLockPath(root);
  if (!existsSync(path)) return emptyGraph(pkgName);
  const lock = readPnpmLock(path);
  if (!lock) return emptyGraph(pkgName);

  const nodes = new Map<string, FlatNode>();
  const snapshots = lock.snapshots ?? {};
  const packages = lock.packages ?? {};
  const keys = new Set([...Object.keys(packages), ...Object.keys(snapshots)]);

  for (const key of keys) {
    const parsed = parsePnpmKey(key);
    if (!parsed) continue;
    const pkgMeta = packages[key];
    const snap = snapshots[key];
    const deps = {
      ...pkgMeta?.dependencies,
      ...snap?.dependencies,
      ...pkgMeta?.optionalDependencies,
      ...snap?.optionalDependencies,
    };
    const node: FlatNode = {
      id: key,
      name: parsed.name,
      version: parsed.version,
      deps: Object.entries(deps).map(([name, spec]) => ({ name, spec: String(spec) })),
    };
    nodes.set(key, node);
    // A peer snapshot (`foo@1.0.0(bar@2)`) holds the edges. The bare `packages` entry often does not.
    const short = `${parsed.name}@${parsed.version}`;
    const previous = nodes.get(short);
    if (!previous || (previous.deps.length === 0 && node.deps.length > 0)) {
      nodes.set(short, node);
    }
  }

  const directs: DirectDep[] = [];
  const catalogs = readCatalogs(root);
  const importers = lock.importers ?? { ".": lock };
  for (const [key, importer] of Object.entries(importers)) {
    const importerName = importerPackageName(root, key);
    pushImporterBag(directs, nodes, importer.dependencies, "prod", importerName, catalogs);
    pushImporterBag(directs, nodes, importer.devDependencies, "dev", importerName, catalogs);
    pushImporterBag(directs, nodes, importer.optionalDependencies, "opt", importerName, catalogs);
  }

  return analyzeFlatGraph(pkgName, nodes, directs, (from, depName, spec) =>
    resolvePnpmDep(nodes, from, depName, spec),
  );
}

function pushImporterBag(
  directs: DirectDep[],
  nodes: Map<string, FlatNode>,
  bag: PnpmImporterBag | undefined,
  kind: DirectDep["bag"],
  importer: string | undefined,
  catalogs: Catalogs,
): void {
  if (!bag) return;
  for (const [name, raw] of Object.entries(bag)) {
    const specifier = typeof raw === "string" ? raw : (raw.specifier ?? "");
    const versionField = typeof raw === "string" ? raw : (raw.version ?? "");
    if (isWorkspaceSpecifier(specifier, versionField)) continue;
    const node =
      resolvePnpmDep(nodes, undefined, name, versionField) ??
      resolvePnpmDep(nodes, undefined, name, specifier);
    if (!node) continue;
    const catalog = catalogSpec(catalogs, specifier, name);
    const range = catalog ? catalog.range || versionField : specifier || versionField;
    directs.push({
      name,
      version: node.version,
      range,
      bag: kind,
      id: node.id,
      ...(importer ? { importer } : {}),
      ...(catalog ? { catalog: catalog.name } : {}),
    });
  }
}

/** The project graph is the last YAML document. A leading boot document only lists pnpm itself. */
function readPnpmLock(path: string): PnpmLock | undefined {
  let text: string;
  try {
    text = readFileSync(path, "utf8");
  } catch {
    return undefined;
  }
  try {
    const docs: PnpmLock[] = [];
    for (const doc of parseAllDocuments(text)) {
      try {
        const value = doc.toJS() as PnpmLock | null;
        if (value && typeof value === "object") docs.push(value);
      } catch {
        // Skip a document that does not decode. The project graph may still follow it.
      }
    }
    const project = docs.filter(
      (doc) => doc.importers || doc.packages || doc.snapshots || doc.dependencies,
    );
    return project.at(-1) ?? docs.at(-1);
  } catch {
    return undefined;
  }
}

export function parsePnpmKey(raw: string): { name: string; version: string } | null {
  let key = raw.trim();
  if (!key || key === ".") return null;
  if (key.startsWith("/")) key = key.slice(1);
  const peer = key.indexOf("(");
  if (peer >= 0) key = key.slice(0, peer);
  const at = key.lastIndexOf("@");
  if (at > 0) {
    const version = key.slice(at + 1).replace(/^npm:/, "");
    if (version) return { name: key.slice(0, at), version };
  }
  const slash = key.lastIndexOf("/");
  if (slash > 0) {
    const version = key.slice(slash + 1);
    if (/^\d/.test(version)) return { name: key.slice(0, slash), version };
  }
  return null;
}

function resolvePnpmDep(
  nodes: Map<string, FlatNode>,
  _from: FlatNode | undefined,
  depName: string,
  spec: string,
): FlatNode | undefined {
  const trimmed = spec.trim();
  const candidates = [
    `${depName}@${trimmed}`,
    trimmed,
    `/${depName}@${trimmed}`,
    `/${trimmed}`,
    trimmed.startsWith("/") ? trimmed.slice(1) : undefined,
  ];
  for (const key of candidates) {
    if (key && nodes.has(key)) return nodes.get(key);
  }
  const parsed = parsePnpmKey(
    trimmed.includes("@") || trimmed.startsWith("/") ? trimmed : `${depName}@${trimmed}`,
  );
  if (parsed) {
    const hit = nodes.get(`${parsed.name}@${parsed.version}`);
    if (hit) return hit;
  }
  return undefined;
}
