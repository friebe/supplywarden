import { existsSync, readFileSync } from "node:fs";
import { maxSatisfying, valid } from "semver";
import type { Advisory, PackageAlertGroup, Severity } from "../types.js";

export type DependabotAlert = {
  number?: number;
  state?: string;
  dependency?: {
    package?: { name?: string; ecosystem?: string };
    manifest_path?: string;
  };
  security_advisory?: {
    ghsa_id?: string;
    cve_id?: string;
    severity?: string;
    summary?: string;
  };
  security_vulnerability?: {
    vulnerable_version_range?: string;
    first_patched_version?: { identifier?: string };
  };
};

const SEVERITY_RANK: Record<Severity, number> = {
  critical: 4,
  high: 3,
  medium: 2,
  low: 1,
  unknown: 0,
};

export function severityRank(value: Severity): number {
  return SEVERITY_RANK[value] ?? 0;
}

export function severityAtLeast(value: Severity, min: Severity): boolean {
  return severityRank(value) >= severityRank(min);
}

export function normalizeSeverity(value?: string): Severity {
  const v = (value ?? "").toLowerCase();
  if (v === "moderate") return "medium";
  if (v === "critical" || v === "high" || v === "medium" || v === "low") return v;
  return "unknown";
}

export function parseAlert(raw: unknown): DependabotAlert {
  if (!raw || typeof raw !== "object") throw new Error("Alert JSON is not an object");
  return raw as DependabotAlert;
}

export function loadAlertFile(path: string): DependabotAlert | DependabotAlert[] {
  if (!existsSync(path)) throw new Error(`Alert file not found: ${path}`);
  const parsed = JSON.parse(readFileSync(path, "utf8")) as unknown;
  if (Array.isArray(parsed)) return parsed.map(parseAlert);
  return parseAlert(parsed);
}

export function alertToAdvisory(alert: DependabotAlert): Advisory {
  return {
    ghsaId: alert.security_advisory?.ghsa_id,
    cveId: alert.security_advisory?.cve_id ?? undefined,
    severity: normalizeSeverity(alert.security_advisory?.severity),
    vulnerableRange: alert.security_vulnerability?.vulnerable_version_range ?? "*",
    patchedVersion: alert.security_vulnerability?.first_patched_version?.identifier,
  };
}

export function maxSeverity(advisories: Advisory[]): Severity {
  return advisories.reduce<Severity>((acc, a) => {
    return SEVERITY_RANK[a.severity] > SEVERITY_RANK[acc] ? a.severity : acc;
  }, "unknown");
}

export function forcedVersionFromAdvisories(advisories: Advisory[]): string | undefined {
  const versions = advisories
    .map((a) => a.patchedVersion)
    .filter((v): v is string => Boolean(v && valid(v)));
  if (versions.length === 0) return undefined;
  return versions.sort((a, b) => (maxSatisfying([a, b], "*") === a ? -1 : 1))[versions.length - 1];
}

/** Highest patched version that closes all advisories. */
export function highestPatchedVersion(advisories: Advisory[]): string | undefined {
  const versions = advisories
    .map((a) => a.patchedVersion)
    .filter((v): v is string => Boolean(v && valid(v)));
  if (!versions.length) return undefined;
  let best = versions[0]!;
  for (const v of versions.slice(1)) {
    if (compareVersions(v, best) > 0) best = v;
  }
  return best;
}

function compareVersions(a: string, b: string): number {
  const pa = a.split(".").map(Number);
  const pb = b.split(".").map(Number);
  for (let i = 0; i < Math.max(pa.length, pb.length); i++) {
    const da = pa[i] ?? 0;
    const db = pb[i] ?? 0;
    if (da > db) return 1;
    if (da < db) return -1;
  }
  return 0;
}

export function groupAlerts(alerts: DependabotAlert[]): PackageAlertGroup[] {
  const map = new Map<string, PackageAlertGroup>();
  for (const alert of alerts) {
    const pkg = alert.dependency?.package?.name;
    if (!pkg) continue;
    const manifestPath = alert.dependency?.manifest_path ?? "package.json";
    const key = `${pkg}::${manifestPath}`;
    const advisory = alertToAdvisory(alert);
    const existing = map.get(key);
    if (!existing) {
      map.set(key, {
        package: pkg,
        manifestPath,
        advisories: [advisory],
        maxSeverity: advisory.severity,
        forcedVersion: advisory.patchedVersion,
        mergedVulnerableRange: advisory.vulnerableRange,
      });
      continue;
    }
    existing.advisories.push(advisory);
    existing.maxSeverity = maxSeverity(existing.advisories);
    existing.forcedVersion = highestPatchedVersion(existing.advisories);
    existing.mergedVulnerableRange = existing.advisories
      .map((a) => a.vulnerableRange)
      .join(" || ");
  }
  return [...map.values()];
}

export function alertsFromInput(input: DependabotAlert | DependabotAlert[]): DependabotAlert[] {
  return Array.isArray(input) ? input : [input];
}
