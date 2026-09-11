import { stillVulnerable } from "../decision/engine.js";
import { analyzeNpmGraph } from "../graph/npm.js";
import type { Advisory, AuditClient, ValidationIssue } from "../types.js";

export async function runPostVerify(opts: {
  cwd: string;
  pkg: string;
  forcedVersion: string;
  advisories: Advisory[];
  audit?: AuditClient;
}): Promise<ValidationIssue[]> {
  const issues: ValidationIssue[] = [];
  const graph = analyzeNpmGraph(opts.cwd, opts.pkg);

  const remainingVulnerable = graph.versions.filter((v) => stillVulnerable(v, opts.advisories));
  if (remainingVulnerable.length) {
    issues.push({
      code: "VERIFY_FAILED",
      message: `${opts.pkg} still resolved to vulnerable version(s): ${remainingVulnerable.join(", ")}`,
      blocking: true,
    });
  }

  if (opts.audit) {
    const result = await opts.audit.audit(opts.cwd);
    const stillOpen = result.vulnerabilities.filter(
      (v) =>
        v.package === opts.pkg &&
        (v.severity === "high" || v.severity === "critical") &&
        opts.advisories.some((a) => a.severity === v.severity || true),
    );
    if (stillOpen.length) {
      issues.push({
        code: "VERIFY_FAILED",
        message: `Audit still reports ${stillOpen.length} finding(s) for ${opts.pkg}`,
        blocking: true,
      });
    }
  }

  return issues;
}
