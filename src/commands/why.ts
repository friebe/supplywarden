import { analyzeNpmGraph } from "../graph/npm.js";
import { nowIso } from "../util/time.js";
import type { CommandResult } from "../types.js";

export function runWhy(opts: { cwd: string; package: string }): CommandResult {
  const graph = analyzeNpmGraph(opts.cwd, opts.package);
  const messages = [
    graph.inTree
      ? `${opts.package} resolved as ${graph.versions.join(", ")}`
      : `${opts.package} not found in lockfile`,
    `Roots: ${graph.roots.map((r) => r.name).join(", ") || "—"}`,
    ...graph.chains.map((c) => c.path.join(" → ")),
  ];
  return {
    exitCode: graph.inTree ? 0 : 1,
    messages,
    report: {
      title: `why ${opts.package}`,
      generatedAt: nowIso(),
      cwd: opts.cwd,
      summary: { inTree: graph.inTree ? 1 : 0, roots: graph.roots.length },
      entries: [],
    },
  };
}
