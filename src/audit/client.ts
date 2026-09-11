import { execFile } from "node:child_process";
import { promisify } from "node:util";
import { groupAlerts, severityAtLeast } from "../alerts/dependabot.js";
import { stillVulnerable } from "../decision/engine.js";
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
import { parseNpmAuditJson } from "./parse.js";

const execFileAsync = promisify(execFile);

export function createStaticAudit(findings: AuditFinding[], error?: string): AuditClient {
  return {
    async audit() {
      return { vulnerabilities: findings, error };
    },
  };
}

function auditCommand(pm: PackageManager | "unknown"): { cmd: string; args: string[] } {
  if (pm === "pnpm") return { cmd: "pnpm", args: ["audit", "--json"] };
  if (pm === "yarn") return { cmd: "yarn", args: ["npm", "audit", "--json"] };
  return { cmd: "npm", args: ["audit", "--json"] };
}

async function runAuditProcess(cmd: string, args: string[], cwd: string): Promise<string> {
  try {
    const { stdout } = await execFileAsync(cmd, args, {
      cwd,
      encoding: "utf8",
      maxBuffer: 20 * 1024 * 1024,
      timeout: 120_000,
    });
    return stdout;
  } catch (err) {
    const stdout = (err as { stdout?: string }).stdout;
    if (typeof stdout === "string" && stdout.trim()) return stdout;
    throw err;
  }
}

export function createLiveAudit(): AuditClient {
  return {
    async audit(cwd: string): Promise<AuditResult> {
      const pm = detectPackageManager(cwd);
      const { cmd, args } = auditCommand(pm);
      try {
        const stdout = await runAuditProcess(cmd, args, cwd);
        return { vulnerabilities: parseNpmAuditJson(stdout) };
      } catch (err) {
        return {
          vulnerabilities: [],
          error: (err as Error).message || `${cmd} audit failed`,
        };
      }
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
  return active.some((entry) => !stillVulnerable(entry.forcedVersion, [advisory]));
}

export function uncoveredFindings(
  findings: AuditFinding[],
  entries: MetadataEntry[],
): AuditFinding[] {
  return findings.filter((finding) => !isFindingCovered(finding, entries));
}
