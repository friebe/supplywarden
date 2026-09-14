import { groupAlerts, severityAtLeast } from "../alerts/dependabot.js";
import { specFloorSafe } from "../util/semver-spec.js";
import { detectPackageManager } from "../graph/npm.js";
import type {
  Advisory,
  AuditClient,
  AuditFinding,
  AuditResult,
  MetadataEntry,
  PackageAlertGroup,
  PackageManager,
  Severity,
} from "../types.js";
import { execPm } from "../util/pm-exec.js";
import { parseNpmAuditJson } from "./parse.js";

export function createStaticAudit(findings: AuditFinding[], error?: string): AuditClient {
  return {
    async audit() {
      return { vulnerabilities: findings, error };
    },
  };
}

function auditArgSets(pm: PackageManager): string[][] {
  if (pm === "yarn") return [["audit", "--json"], ["npm", "audit", "--json"]];
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
          return { vulnerabilities: parseNpmAuditJson(stdout) };
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

function advisoryForFinding(finding: AuditFinding): Advisory {
  return {
    ghsaId: finding.ghsaId,
    cveId: finding.cveId,
    severity: finding.severity,
    vulnerableRange: finding.range ?? "*",
    patchedVersion: finding.patchedVersion,
  };
}

export function isFindingCovered(finding: AuditFinding, entries: MetadataEntry[]): boolean {
  const active = entries.filter(
    (e) =>
      e.package === finding.package &&
      (e.status === "active" || e.status === "pending_verify"),
  );
  if (!active.length) return false;
  const advisory = advisoryForFinding(finding);
  return active.some((entry) => specFloorSafe(entry.forcedVersion, [advisory]));
}

export function uncoveredFindings(
  findings: AuditFinding[],
  entries: MetadataEntry[],
): AuditFinding[] {
  return findings.filter((finding) => !isFindingCovered(finding, entries));
}
