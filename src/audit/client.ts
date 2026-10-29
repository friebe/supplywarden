import { groupAlerts, severityAtLeast } from "../alerts/dependabot.js";
import { detectPackageManager } from "../graph/npm.js";
import type {
  AuditClient,
  AuditFinding,
  AuditResult,
  PackageAlertGroup,
  PackageManager,
  Severity,
} from "../types.js";
import { execPm } from "../util/pm-exec.js";
import { auditFailureMessage, parseNpmAuditJson } from "./parse.js";

export function createStaticAudit(findings: AuditFinding[], error?: string): AuditClient {
  return {
    async audit() {
      return { vulnerabilities: findings, error };
    },
  };
}

function auditArgSets(pm: PackageManager): string[][] {
  if (pm === "yarn")
    return [
      ["audit", "--json"],
      ["npm", "audit", "--json"],
    ];
  return [["audit", "--json"]];
}

export function createLiveAudit(): AuditClient {
  return {
    async audit(cwd: string): Promise<AuditResult> {
      const detected = detectPackageManager(cwd);
      const pm: PackageManager = detected === "unknown" ? "npm" : detected;
      let lastError: string | undefined;
      for (const args of auditArgSets(pm)) {
        try {
          const { stdout } = await execPm(pm, args, { cwd, timeout: 120_000 });
          const vulnerabilities = parseNpmAuditJson(stdout);
          const failure = auditFailureMessage(stdout);
          if (failure && !vulnerabilities.length) return { vulnerabilities: [], error: failure };
          return { vulnerabilities };
        } catch (err) {
          lastError = (err as Error).message || `${pm} ${args.join(" ")} failed`;
        }
      }
      return { vulnerabilities: [], error: lastError ?? `${pm} audit failed` };
    },
  };
}

export function filterFindings(findings: AuditFinding[], minSeverity: Severity): AuditFinding[] {
  return findings.filter((f) => severityAtLeast(f.severity, minSeverity));
}

export function findingsToGroups(findings: AuditFinding[]): PackageAlertGroup[] {
  return groupAlerts(
    findings.map((finding) => ({
      dependency: {
        package: { name: finding.package, ecosystem: "npm" },
        manifest_path: "package.json",
      },
      security_advisory: {
        ghsa_id: finding.ghsaId,
        cve_id: finding.cveId,
        severity: finding.severity,
        summary: finding.title,
      },
      security_vulnerability: {
        vulnerable_version_range: finding.range ?? "*",
        first_patched_version: finding.patchedVersion
          ? { identifier: finding.patchedVersion }
          : undefined,
      },
    })),
  );
}
