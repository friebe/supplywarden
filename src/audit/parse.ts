import { minVersion } from "semver";
import { normalizeSeverity } from "../alerts/dependabot.js";
import type { AuditFinding } from "../types.js";

type AuditVia = {
  name?: string;
  dependency?: string;
  title?: string;
  url?: string;
  severity?: string;
  range?: string;
  cves?: string[];
};

type AuditV2Entry = {
  name?: string;
  severity?: string;
  range?: string;
  via?: Array<string | AuditVia>;
};

type AuditV1Advisory = {
  github_advisory_id?: string;
  ghsa?: string;
  cves?: string[];
  module_name?: string;
  vulnerable_versions?: string;
  patched_versions?: string;
  severity?: string;
  title?: string;
  url?: string;
};

type YarnAdvisoryLine = {
  type?: string;
  data?: {
    advisory?: AuditV1Advisory;
  };
};

function ghsaFrom(value?: string, url?: string): string | undefined {
  const fromValue = value?.match(/GHSA-[0-9a-z-]+/i)?.[0];
  if (fromValue) return fromValue;
  return url?.match(/GHSA-[0-9a-z-]+/i)?.[0];
}

function cveFrom(cves?: string[]): string | undefined {
  return cves?.find((c) => /^CVE-/i.test(c));
}

function patchedFromPatchedRange(range?: string): string | undefined {
  if (!range || range === "<0.0.0") return undefined;
  try {
    return minVersion(range)?.version;
  } catch {
    return undefined;
  }
}

function patchedFromVulnerableRange(range?: string): string | undefined {
  if (!range) return undefined;
  const match = range.trim().match(/^<\s*=?\s*(\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?)/);
  return match?.[1];
}

function findingKey(finding: AuditFinding): string {
  return `${finding.package}|${finding.ghsaId ?? finding.range ?? finding.title ?? ""}`;
}

function collect(findings: AuditFinding[]): AuditFinding[] {
  const map = new Map<string, AuditFinding>();
  for (const finding of findings) {
    const key = findingKey(finding);
    if (!map.has(key)) map.set(key, finding);
  }
  return [...map.values()];
}

function parseV2(raw: { vulnerabilities?: Record<string, AuditV2Entry> }): AuditFinding[] {
  const findings: AuditFinding[] = [];
  for (const [pkg, entry] of Object.entries(raw.vulnerabilities ?? {})) {
    const vias = (entry.via ?? []).filter((via): via is AuditVia => typeof via === "object" && via !== null);
    if (!vias.length) continue;
    for (const via of vias) {
      const name = via.name ?? via.dependency ?? entry.name ?? pkg;
      const range = via.range ?? entry.range;
      findings.push({
        package: name,
        severity: normalizeSeverity(via.severity ?? entry.severity),
        range,
        ghsaId: ghsaFrom(undefined, via.url),
        title: via.title,
        patchedVersion: patchedFromVulnerableRange(range),
      });
    }
  }
  return findings;
}

function parseV1(raw: { advisories?: Record<string, AuditV1Advisory> }): AuditFinding[] {
  const findings: AuditFinding[] = [];
  for (const advisory of Object.values(raw.advisories ?? {})) {
    const name = advisory.module_name;
    if (!name) continue;
    const range = advisory.vulnerable_versions;
    findings.push({
      package: name,
      severity: normalizeSeverity(advisory.severity),
      range,
      ghsaId: ghsaFrom(advisory.github_advisory_id ?? advisory.ghsa, advisory.url),
      cveId: cveFrom(advisory.cves),
      title: advisory.title,
      patchedVersion: patchedFromPatchedRange(advisory.patched_versions) ?? patchedFromVulnerableRange(range),
    });
  }
  return findings;
}

function parseNdjson(text: string): AuditFinding[] {
  const findings: AuditFinding[] = [];
  for (const line of text.split(/\r?\n/)) {
    const trimmed = line.trim();
    if (!trimmed.startsWith("{")) continue;
    try {
      const parsed = JSON.parse(trimmed) as YarnAdvisoryLine;
      if (parsed.type !== "auditAdvisory" || !parsed.data?.advisory) continue;
      const advisory = parsed.data.advisory;
      const name = advisory.module_name;
      if (!name) continue;
      const range = advisory.vulnerable_versions;
      findings.push({
        package: name,
        severity: normalizeSeverity(advisory.severity),
        range,
        ghsaId: ghsaFrom(advisory.github_advisory_id ?? advisory.ghsa, advisory.url),
        cveId: cveFrom(advisory.cves),
        title: advisory.title,
        patchedVersion: patchedFromPatchedRange(advisory.patched_versions) ?? patchedFromVulnerableRange(range),
      });
    } catch {
      continue;
    }
  }
  return findings;
}

export function parseNpmAuditJson(stdout: string | unknown): AuditFinding[] {
  if (typeof stdout === "string") {
    const trimmed = stdout.trim();
    if (!trimmed) return [];
    try {
      return parseNpmAuditJson(JSON.parse(trimmed));
    } catch {
      const start = trimmed.indexOf("{");
      const end = trimmed.lastIndexOf("}");
      if (start >= 0 && end > start) {
        try {
          return parseNpmAuditJson(JSON.parse(trimmed.slice(start, end + 1)));
        } catch {
          return collect(parseNdjson(trimmed));
        }
      }
      return collect(parseNdjson(trimmed));
    }
  }
  if (Array.isArray(stdout)) {
    return collect(stdout.flatMap((item) => parseNpmAuditJson(item)));
  }
  if (!stdout || typeof stdout !== "object") return [];
  const obj = stdout as {
    auditReportVersion?: number;
    vulnerabilities?: Record<string, AuditV2Entry>;
    advisories?: Record<string, AuditV1Advisory>;
  };
  if (obj.vulnerabilities && typeof obj.vulnerabilities === "object") {
    return collect(parseV2(obj));
  }
  if (obj.advisories && typeof obj.advisories === "object") {
    return collect(parseV1(obj));
  }
  return [];
}
