import type { DependencyChain, DependencyKind, GraphAnalysis, RootPackage } from "../types.js";
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
  return { package: pkgName, versions: [], inTree: false, roots: [], chains: [], dependerRanges: [] };
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
        if (edge?.spec) dependerRanges.add(edge.spec);
      } else if (origin.name === pkgName) {
        dependerRanges.add(origin.range);
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
