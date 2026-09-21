import { existsSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { parse as parseYaml } from "yaml";
import type { GraphAnalysis } from "../types.js";
import { analyzeFlatGraph, emptyGraph, type DirectDep, type FlatNode } from "./flat.js";

export function yarnLockPath(cwd: string): string {
  return join(cwd, "yarn.lock");
}

export function hasYarnLock(cwd: string): boolean {
  return existsSync(yarnLockPath(cwd));
}

export function analyzeYarnGraph(cwd: string, pkgName: string): GraphAnalysis {
  const path = yarnLockPath(cwd);
  if (!existsSync(path)) return emptyGraph(pkgName);
  const text = readFileSync(path, "utf8");
  const nodes = new Map<string, FlatNode>();
  const byName = new Map<string, FlatNode[]>();

  if (text.includes("# yarn lockfile v1")) {
    loadYarnClassic(text, nodes, byName);
  } else {
    loadYarnBerry(text, nodes, byName);
  }

  const directs = directDepsFromManifest(cwd, nodes, byName);
  return analyzeFlatGraph(pkgName, nodes, directs, (_from, depName, spec) =>
    resolveYarnDep(nodes, byName, depName, spec),
  );
}

function indexNode(nodes: Map<string, FlatNode>, byName: Map<string, FlatNode[]>, node: FlatNode, aliases: string[]): void {
  nodes.set(node.id, node);
  for (const alias of aliases) nodes.set(alias, node);
  const list = byName.get(node.name) ?? [];
  if (!list.some((n) => n.id === node.id)) list.push(node);
  byName.set(node.name, list);
}

function loadYarnClassic(text: string, nodes: Map<string, FlatNode>, byName: Map<string, FlatNode[]>): void {
  const blocks = splitYarnClassicBlocks(text);
  for (const block of blocks) {
    const header = block[0];
    if (!header) continue;
    const descriptors = header
      .replace(/:$/, "")
      .trim()
      .split(/,\s*/)
      .map((d) => d.replace(/^"|"$/g, ""));
    let version = "";
    const deps: Record<string, string> = {};
    let inDeps = false;
    for (const line of block.slice(1)) {
      const trimmed = line.trim();
      if (trimmed === "dependencies:" || trimmed === "optionalDependencies:") {
        inDeps = true;
        continue;
      }
      if (!line.startsWith("    ") && trimmed.includes(" ") && !trimmed.endsWith(":")) {
        inDeps = false;
      }
      if (trimmed.startsWith("version ")) {
        version = unquote(trimmed.slice("version ".length));
        continue;
      }
      if (inDeps && line.startsWith("    ")) {
        const parsed = parseYarnClassicDep(trimmed);
        if (parsed) deps[parsed.name] = parsed.spec;
      }
    }
    if (!version || !descriptors.length) continue;
    const name = parseYarnDescriptor(descriptors[0]!).name;
    const node: FlatNode = {
      id: `${name}@${version}`,
      name,
      version,
      deps: Object.entries(deps).map(([depName, spec]) => ({ name: depName, spec })),
    };
    indexNode(nodes, byName, node, [`${name}@${version}`, ...descriptors.map((d) => `${name}@${parseYarnDescriptor(d).range}`)]);
  }
}

function splitYarnClassicBlocks(text: string): string[][] {
  const blocks: string[][] = [];
  let current: string[] = [];
  for (const raw of text.split(/\r?\n/)) {
    if (raw.startsWith("#") || raw.startsWith("\t#")) continue;
    if (!raw.trim()) {
      if (current.length) {
        blocks.push(current);
        current = [];
      }
      continue;
    }
    if (!raw.startsWith(" ") && !raw.startsWith("\t") && current.length) {
      blocks.push(current);
      current = [raw];
      continue;
    }
    current.push(raw);
  }
  if (current.length) blocks.push(current);
  return blocks;
}

function parseYarnClassicDep(line: string): { name: string; spec: string } | undefined {
  const quoted = line.match(/^"([^"]+)"\s+"([^"]+)"$/);
  if (quoted) return { name: quoted[1]!, spec: quoted[2]! };
  const plain = line.match(/^(\S+)\s+"([^"]+)"$/);
  if (plain) return { name: plain[1]!, spec: plain[2]! };
  return undefined;
}

function loadYarnBerry(text: string, nodes: Map<string, FlatNode>, byName: Map<string, FlatNode[]>): void {
  let parsed: unknown;
  try {
    parsed = parseYaml(text);
  } catch {
    return;
  }
  if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) return;
  for (const [key, value] of Object.entries(parsed as Record<string, unknown>)) {
    if (key === "__metadata" || !value || typeof value !== "object") continue;
    const meta = value as { version?: string; dependencies?: Record<string, string>; optionalDependencies?: Record<string, string> };
    if (!meta.version) continue;
    const descriptors = key.split(/,\s*/).map((d) => d.replace(/^"|"$/g, ""));
    const name = parseYarnDescriptor(descriptors[0] ?? key).name;
    const deps = { ...(meta.dependencies ?? {}), ...(meta.optionalDependencies ?? {}) };
    const node: FlatNode = {
      id: `${name}@${meta.version}`,
      name,
      version: String(meta.version),
      deps: Object.entries(deps).map(([depName, spec]) => ({ name: depName, spec: String(spec) })),
    };
    indexNode(nodes, byName, node, [`${name}@${meta.version}`, ...descriptors]);
  }
}

function directDepsFromManifest(
  cwd: string,
  nodes: Map<string, FlatNode>,
  byName: Map<string, FlatNode[]>,
): DirectDep[] {
  const pkgPath = join(cwd, "package.json");
  if (!existsSync(pkgPath)) return [];
  let pkg: {
    dependencies?: Record<string, string>;
    devDependencies?: Record<string, string>;
    optionalDependencies?: Record<string, string>;
  };
  try {
    pkg = JSON.parse(readFileSync(pkgPath, "utf8")) as typeof pkg;
  } catch {
    return [];
  }
  const directs: DirectDep[] = [];
  const bags: Array<[Record<string, string> | undefined, DirectDep["bag"]]> = [
    [pkg.dependencies as Record<string, string> | undefined, "prod"],
    [pkg.devDependencies as Record<string, string> | undefined, "dev"],
    [pkg.optionalDependencies as Record<string, string> | undefined, "opt"],
  ];
  for (const [bag, kind] of bags) {
    if (!bag) continue;
    for (const [name, range] of Object.entries(bag)) {
      if (typeof range !== "string") continue;
      const node = resolveYarnDep(nodes, byName, name, range);
      if (!node) continue;
      directs.push({ name, version: node.version, range, bag: kind, id: node.id });
    }
  }
  return directs;
}

function resolveYarnDep(
  nodes: Map<string, FlatNode>,
  byName: Map<string, FlatNode[]>,
  depName: string,
  spec: string,
): FlatNode | undefined {
  const cleaned = spec.replace(/^npm:/, "").replace(/^"|"$/g, "");
  const exact = nodes.get(`${depName}@${cleaned}`) ?? nodes.get(`${depName}@${spec}`);
  if (exact) return exact;
  const list = byName.get(depName) ?? [];
  return list.find((n) => n.version === cleaned) ?? list[0];
}

export function parseYarnDescriptor(raw: string): { name: string; range: string } {
  const s = raw.replace(/^"|"$/g, "").trim();
  const npmAt = s.lastIndexOf("@npm:");
  if (npmAt > 0) return { name: s.slice(0, npmAt), range: s.slice(npmAt + 5) };
  const at = s.lastIndexOf("@");
  if (at > 0) return { name: s.slice(0, at), range: s.slice(at + 1) };
  return { name: s, range: "*" };
}

function unquote(value: string): string {
  const t = value.trim();
  if ((t.startsWith('"') && t.endsWith('"')) || (t.startsWith("'") && t.endsWith("'"))) {
    return t.slice(1, -1);
  }
  return t;
}
