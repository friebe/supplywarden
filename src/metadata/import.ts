import { addDaysIso, nowIso } from "../util/time.js";
import { actorName } from "../config.js";
import { resolvePackageManager } from "../graph/npm.js";
import type { GraphAnalysis, MetadataEntry, SupplywardenConfig } from "../types.js";
import { extractExistingOverrides, readPackageJson } from "./sync.js";
import { newEntryId } from "./store.js";

export function importOverridesFromPackageJson(
  cwd: string,
  config: SupplywardenConfig,
  graphFor: (pkg: string) => GraphAnalysis,
): MetadataEntry[] {
  const pkg = readPackageJson(cwd);
  const found = extractExistingOverrides(pkg);
  const createdAt = nowIso();
  const reviewBy = addDaysIso(config.defaultReviewDays);

  return found.map((item) => {
    const graph = graphFor(item.package);
    const reason =
      graph.roots.length > 0
        ? `${graph.roots.length} root package(s): ${graph.roots.map((r) => r.name).join(", ")}; override imported from unknown date`
        : `Imported from package.json – ${item.package}@${item.version}`;

    return {
      id: newEntryId(),
      status: "active",
      package: item.package,
      forcedVersion: item.version,
      scope: item.scope,
      advisories: [],
      reason,
      strategy: "override",
      rootPackages: graph.roots.map((r) => r.name),
      dependencyChains: graph.chains.map((c) => c.path.join(" → ")),
      packageManager: resolvePackageManager(cwd),
      manifestPath: "package.json",
      createdAt,
      createdBy: actorName(),
      reviewBy,
      reviewReason: "Imported override – confirm advisory and whether root upgrade is possible",
      needsReview: true,
    } satisfies MetadataEntry;
  });
}
