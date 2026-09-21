import { existsSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { parse as parseYaml } from "yaml";
import type { GraphAnalysis } from "../types.js";
import { analyzeFlatGraph, emptyGraph, type DirectDep, type FlatNode } from "./flat.js";

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
  return existsSync(pnpmLockPath(cwd));
}

export function analyzePnpmGraph(cwd: string, pkgName: string): GraphAnalysis {
  const path = pnpmLockPath(cwd);
  if (!existsSync(path)) return emptyGraph(pkgName);
  let lock: PnpmLock;
  try {
    lock = parseYaml(readFileSync(path, "utf8")) as PnpmLock;
  } catch {
    return emptyGraph(pkgName);
  }

  const nodes = new Map<string, FlatNode>();
  const snapshots = lock.snapshots ?? {};
  const packages = lock.packages ?? {};
  const keys = new Set([...Object.keys(packages), ...Object.keys(snapshots)]);

  for (const key of keys) {
    const parsed = parsePnpmKey(key);
    if (!parsed) continue;
    const snap = snapshots[key] ?? packages[key] ?? {};
    const deps = {
      ...(packages[key]?.dependencies ?? {}),
      ...(snap.dependencies ?? {}),
      ...(packages[key]?.optionalDependencies ?? {}),
      ...(snap.optionalDependencies ?? {}),
    };
    const node: FlatNode = {
      id: key,
      name: parsed.name,
      version: parsed.version,
      deps: Object.entries(deps).map(([name, spec]) => ({ name, spec: String(spec) })),
    };
    nodes.set(key, node);
    if (!nodes.has(`${parsed.name}@${parsed.version}`)) {
      nodes.set(`${parsed.name}@${parsed.version}`, node);
    }
  }

  const directs: DirectDep[] = [];
  const importers = lock.importers ?? { ".": lock };
  for (const importer of Object.values(importers)) {
    pushImporterBag(directs, nodes, importer.dependencies, "prod");
    pushImporterBag(directs, nodes, importer.devDependencies, "dev");
    pushImporterBag(directs, nodes, importer.optionalDependencies, "opt");
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
): void {
  if (!bag) return;
  for (const [name, raw] of Object.entries(bag)) {
    const specifier = typeof raw === "string" ? raw : raw.specifier ?? "";
    const versionField = typeof raw === "string" ? raw : raw.version ?? "";
    const node = resolvePnpmDep(nodes, undefined, name, versionField) ?? resolvePnpmDep(nodes, undefined, name, specifier);
    if (!node) continue;
    directs.push({
      name,
      version: node.version,
      range: specifier || versionField,
      bag: kind,
      id: node.id,
    });
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
  const parsed = parsePnpmKey(trimmed.includes("@") || trimmed.startsWith("/") ? trimmed : `${depName}@${trimmed}`);
  if (parsed) {
    const hit = nodes.get(`${parsed.name}@${parsed.version}`);
    if (hit) return hit;
  }
  return undefined;
}
