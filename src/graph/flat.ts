import type { DependencyChain, Depender, GraphAnalysis, RootPackage } from "../types.js";
import { inferDependencyKind } from "./kind.js";

export type FlatNode = {
  id: string;
  name: string;
  version: string;
  deps: Array<{ name: string; spec: string }>;
};

export type DirectDep = {
  name: string;
  version: string;
  range: string;
  bag: "prod" | "dev" | "opt";
  id: string;
};

export function emptyGraph(pkgName: string): GraphAnalysis {
  return {
    package: pkgName,
    versions: [],
    inTree: false,
    roots: [],
    chains: [],
    dependerRanges: [],
    dependers: [],
    directs: [],
  };
}

export function analyzeFlatGraph(
  pkgName: string,
  nodes: Map<string, FlatNode>,
  directs: DirectDep[],
  resolveDep: (from: FlatNode, depName: string, spec: string) => FlatNode | undefined,
): GraphAnalysis {
  const chains: DependencyChain[] = [];
  const rootMap = new Map<string, RootPackage>();
  const versions = new Set<string>();
  const dependerRanges = new Set<string>();
  const dependers: Depender[] = [];
  const dependerKeys = new Set<string>();
  const addDepender = (parent: string, range: string, version?: string) => {
    if (!range || parent === pkgName) return;
    const key = `${parent}\0${range}\0${version ?? ""}`;
    if (dependerKeys.has(key)) return;
    dependerKeys.add(key);
    dependers.push({ parent, range, version });
    dependerRanges.add(range);
  };
  const copies: Array<{ dev?: boolean; optional?: boolean }> = [];
  const chainKeys = new Set<string>();

  const visit = (node: FlatNode, path: FlatNode[], origin: DirectDep, seen: Set<string>) => {
    if (node.name === pkgName) {
      versions.add(node.version);
      copies.push({
        dev: origin.bag === "dev",
        optional: origin.bag === "opt",
      });
      const chainPath = path.map((n) => `${n.name}@${n.version}`);
      const key = chainPath.join(">");
      if (!chainKeys.has(key)) {
        chainKeys.add(key);
        chains.push({ path: chainPath, package: pkgName, version: node.version });
      }
      rootMap.set(origin.name, {
        name: origin.name,
        version: origin.version,
        range: origin.range,
      });
      const parent = path.length >= 2 ? path[path.length - 2] : undefined;
      if (parent) {
        const edge = parent.deps.find((d) => d.name === pkgName);
        if (edge?.spec) addDepender(parent.name, edge.spec, parent.version);
      } else if (origin.name === pkgName) {
        addDepender("the project", origin.range);
      }
      return;
    }

    for (const dep of node.deps) {
      const next = resolveDep(node, dep.name, dep.spec);
      if (!next || seen.has(next.id)) continue;
      seen.add(next.id);
      visit(next, [...path, next], origin, seen);
      seen.delete(next.id);
    }
  };

  for (const direct of directs) {
    const start = nodes.get(direct.id);
    if (!start) continue;
    visit(start, [start], direct, new Set([start.id]));
  }

  const roots = [...rootMap.values()];
  const inTree = versions.size > 0;
  return {
    package: pkgName,
    versions: [...versions],
    inTree,
    roots,
    chains,
    dependerRanges: [...dependerRanges],
    dependers: dependers.sort((a, b) => a.parent.localeCompare(b.parent)),
    directs: directs.map((dep) => ({ name: dep.name, version: dep.version })),
    dependencyKind: inTree
      ? inferDependencyKind({
          pkgName,
          copies,
          rootNames: roots.map((r) => r.name),
          rootDependencies: Object.fromEntries(
            directs.filter((d) => d.bag === "prod").map((d) => [d.name, d.range]),
          ),
          rootDevDependencies: Object.fromEntries(
            directs.filter((d) => d.bag === "dev").map((d) => [d.name, d.range]),
          ),
          rootOptionalDependencies: Object.fromEntries(
            directs.filter((d) => d.bag === "opt").map((d) => [d.name, d.range]),
          ),
        })
      : undefined,
  };
}
