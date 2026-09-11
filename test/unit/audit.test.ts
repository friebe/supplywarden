import { readFileSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { parseNpmAuditJson } from "../../src/audit/parse.js";
import { filterFindings, isFindingCovered } from "../../src/audit/client.js";
import { FIXTURES_ROOT } from "../helpers/fixture-project.js";
import type { MetadataEntry } from "../../src/types.js";

describe("parseNpmAuditJson", () => {
  it("reads npm audit v2 advisories and skips via-aliases", () => {
    const raw = readFileSync(join(FIXTURES_ROOT, "audit/npm-v2.json"), "utf8");
    const findings = parseNpmAuditJson(raw);
    expect(findings).toHaveLength(1);
    expect(findings[0]).toMatchObject({
      package: "qs",
      severity: "high",
      range: "<6.11.0",
      ghsaId: "GHSA-qs-high",
      patchedVersion: "6.11.0",
    });
  });

  it("reads npm/pnpm audit v1 advisories", () => {
    const raw = readFileSync(join(FIXTURES_ROOT, "audit/npm-v1.json"), "utf8");
    const findings = parseNpmAuditJson(raw);
    expect(findings).toEqual([
      expect.objectContaining({
        package: "qs",
        severity: "high",
        range: "<6.11.0",
        ghsaId: "GHSA-qs-high",
        cveId: "CVE-2022-24999",
        patchedVersion: "6.11.2",
      }),
    ]);
  });

  it("reads yarn classic NDJSON", () => {
    const line = JSON.stringify({
      type: "auditAdvisory",
      data: {
        advisory: {
          module_name: "qs",
          severity: "moderate",
          vulnerable_versions: "< 6.11.0",
          patched_versions: ">= 6.11.2",
          github_advisory_id: "GHSA-qs-high",
        },
      },
    });
    const findings = parseNpmAuditJson(`${line}\n{"type":"auditSummary","data":{}}\n`);
    expect(findings[0]).toMatchObject({
      package: "qs",
      severity: "medium",
      ghsaId: "GHSA-qs-high",
      patchedVersion: "6.11.2",
    });
  });
});

describe("audit coverage", () => {
  const entry = {
    package: "qs",
    status: "active",
    forcedVersion: "6.11.2",
  } as MetadataEntry;

  it("treats a patched override as covering the finding", () => {
    expect(
      isFindingCovered({ package: "qs", severity: "high", range: "< 6.11.0" }, [entry]),
    ).toBe(true);
  });

  it("does not cover a still-vulnerable override", () => {
    expect(
      isFindingCovered(
        { package: "qs", severity: "high", range: "< 6.11.0" },
        [{ ...entry, forcedVersion: "6.10.0" }],
      ),
    ).toBe(false);
  });

  it("filters below min severity", () => {
    expect(
      filterFindings(
        [
          { package: "a", severity: "low" },
          { package: "b", severity: "high" },
        ],
        "high",
      ).map((f) => f.package),
    ).toEqual(["b"]);
  });
});
