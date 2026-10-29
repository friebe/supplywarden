import { specFloorSafe, versionSatisfiesSpec } from "../util/semver-spec.js";
import type {
  Advisory,
  AuditClient,
  GraphAnalysis,
  OverrideScope,
  RegistryClient,
  ValidationIssue,
} from "../types.js";

export async function runPreApplyGate(opts: {
  pkg: string;
  forcedVersion: string;
  graph: GraphAnalysis;
  advisories: Advisory[];
  scope: OverrideScope;
  existing: Array<{ package: string; forcedVersion: string }>;
  registry?: RegistryClient;
  audit?: AuditClient;
}): Promise<ValidationIssue[]> {
  const issues: ValidationIssue[] = [];

  if (!opts.graph.inTree) {
    issues.push({
      code: "NOT_IN_TREE",
      message: `${opts.pkg} is not in the dependency tree`,
      blocking: true,
    });
  }

  if (opts.forcedVersion && !specFloorSafe(opts.forcedVersion, opts.advisories)) {
    issues.push({
      code: "STILL_VULNERABLE",
      message: `${opts.pkg}@${opts.forcedVersion} still matches a vulnerable range`,
      hint: `Vulnerable: ${opts.advisories.map((a) => a.vulnerableRange).join(" || ")}`,
      blocking: true,
    });
  }

  if (
    opts.graph.versions.length === 1 &&
    versionSatisfiesSpec(opts.graph.versions[0]!, opts.forcedVersion)
  ) {
    issues.push({
      code: "NOOP_OVERRIDE",
      message: `Lockfile already resolved ${opts.pkg}@${opts.forcedVersion}; override would not change the graph`,
      blocking: true,
    });
  }

  const scope = opts.scope;
  if (scope.type === "scoped") {
    const parent = scope.parent;
    const parentInTree =
      opts.graph.chains.some((c) =>
        c.path.some((seg) => seg.startsWith(`${parent}@`) || seg === parent),
      ) || opts.graph.roots.some((r) => r.name === parent);
    if (!parentInTree && opts.graph.inTree) {
      issues.push({
        code: "INVALID_SCOPE",
        message: `Scoped parent ${parent} is not on a chain to ${opts.pkg}`,
        blocking: true,
      });
    }
  }

  const conflicting = opts.existing.filter(
    (e) => e.package === opts.pkg && e.forcedVersion !== opts.forcedVersion,
  );
  if (conflicting.length) {
    issues.push({
      code: "CONFLICTING_OVERRIDES",
      message: `Active override ${opts.pkg}@${conflicting[0]!.forcedVersion} conflicts with ${opts.forcedVersion}`,
      hint: "package.json already pins a different version",
      blocking: false,
    });
  }

  if (opts.registry) {
    const verified = await opts.registry.verifyPackageVersion(opts.pkg, opts.forcedVersion);
    if (!verified.exists) {
      issues.push({
        code: "VERSION_NOT_FOUND",
        message: `${opts.pkg}@${opts.forcedVersion} does not exist on the registry`,
        blocking: true,
      });
    } else if (verified.deprecated) {
      issues.push({
        code: "DEPRECATED_VERSION",
        message: `${opts.pkg}@${opts.forcedVersion} is deprecated: ${verified.deprecated}`,
        blocking: false,
      });
    }

    if (opts.registry.advisoriesFor) {
      const extra = await opts.registry.advisoriesFor(opts.pkg, opts.forcedVersion);
      const newHigh = extra.filter(
        (a) =>
          (a.severity === "high" || a.severity === "critical") &&
          !opts.advisories.some((known) => known.ghsaId && known.ghsaId === a.ghsaId),
      );
      if (newHigh.length) {
        issues.push({
          code: "INTRODUCES_VULN",
          message: `${opts.pkg}@${opts.forcedVersion} introduces ${newHigh.length} high/critical advisory(ies)`,
          blocking: true,
        });
      }
    }
  }

  return issues;
}

export function blockingIssues(issues: ValidationIssue[]): ValidationIssue[] {
  return issues.filter((i) => i.blocking);
}
