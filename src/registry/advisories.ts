import { severityAtLeast, normalizeSeverity } from "../alerts/dependabot.js";
import type { Advisory, Severity } from "../types.js";

const BULK_URL = "https://registry.npmjs.org/-/npm/v1/security/advisories/bulk";

type BulkAdvisory = {
  url?: string;
  title?: string;
  severity?: string;
  vulnerable_versions?: string;
  cves?: string[];
};

/** One registry round-trip for every version that would be installed without an override. */
export async function fetchAdvisories(
  specs: Array<{ package: string; version: string }>,
): Promise<Map<string, Advisory[] | undefined>> {
  const map = new Map<string, Advisory[] | undefined>();
  const body: Record<string, string[]> = {};
  for (const spec of specs) {
    const key = advisoryKey(spec.package, spec.version);
    if (map.has(key)) continue;
    map.set(key, []);
    const versions = body[spec.package] ?? [];
    versions.push(spec.version);
    body[spec.package] = versions;
  }
  if (!map.size) return map;

  try {
    const res = await fetch(BULK_URL, {
      method: "POST",
      headers: { "content-type": "application/json", accept: "application/json" },
      body: JSON.stringify(body),
      signal: AbortSignal.timeout(15_000),
    });
    if (!res.ok) throw new Error(`advisory lookup failed: ${res.status}`);
    const json = (await res.json()) as Record<string, BulkAdvisory[]>;
    for (const spec of specs) {
      const raw = Array.isArray(json[spec.package]) ? json[spec.package]! : [];
      map.set(
        advisoryKey(spec.package, spec.version),
        raw.map(toAdvisory).filter((advisory): advisory is Advisory => advisory !== null),
      );
    }
    return map;
  } catch {
    for (const key of map.keys()) map.set(key, undefined);
    return map;
  }
}

export function advisoryKey(pkg: string, version: string): string {
  return `${pkg}@${version}`;
}

export function advisoriesAtSeverity(advisories: Advisory[], min: Severity): Advisory[] {
  return advisories.filter((advisory) => severityAtLeast(advisory.severity, min));
}

function toAdvisory(raw: BulkAdvisory): Advisory | null {
  if (!raw.vulnerable_versions) return null;
  const ghsa = raw.url?.match(/GHSA-[0-9a-z-]+/i)?.[0];
  const cve = raw.cves?.find((id) => id.startsWith("CVE-"));
  return {
    ...(ghsa ? { ghsaId: ghsa } : {}),
    ...(cve ? { cveId: cve } : {}),
    ...(raw.title ? { title: raw.title } : {}),
    severity: normalizeSeverity(raw.severity),
    vulnerableRange: raw.vulnerable_versions,
  };
}
