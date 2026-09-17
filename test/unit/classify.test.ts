import { describe, expect, it } from "vitest";
import { classifyEntry, classifyUntrackedOverride, parentRangesAlreadySafe, reconcileWithAudit, removableReasonLabel, sortCheckEntries } from "../../src/check/classify.js";
import { toMarkdown } from "../../src/report/model.js";
import { fixtureDir } from "../helpers/fixture-project.js";
import type { CheckEntry, MetadataEntry } from "../../src/types.js";

describe("classifyEntry", () => {
  it("marks npm-removable as RESOLVED with no-vulnerable-version", () => {
    const result = classifyEntry(fixtureDir("npm-removable"), {
      id: "qs-removable",
      status: "active",
      package: "qs",
      forcedVersion: "6.11.2",
      scope: { type: "global" },
      advisories: [
        { ghsaId: "GHSA-qs-high", severity: "high", vulnerableRange: "< 6.11.0", patchedVersion: "6.11.2" },
      ],
      reason: "historical override",
      strategy: "override",
      rootPackages: ["express"],
      dependencyChains: [],
      packageManager: "npm",
      manifestPath: "package.json",
      createdAt: "2025-01-01T00:00:00.000Z",
      createdBy: "peter",
      reviewBy: "2026-12-01T00:00:00.000Z",
      reviewReason: "check",
    });
    expect(result.statuses).toContain("RESOLVED");
    expect(result.removableReason).toBe("no-vulnerable-version");
    expect(result.roots?.length).toBeGreaterThan(0);
  });

  it("marks leftover override when package.json already depends on the min patched version", () => {
    const result = classifyEntry(fixtureDir("npm-mixed"), {
      id: "lodash-removable",
      status: "active",
      package: "lodash",
      forcedVersion: "4.17.21",
      scope: { type: "global" },
      advisories: [
        {
          ghsaId: "GHSA-35jh-r3h4-6jhm",
          severity: "high",
          vulnerableRange: "< 4.17.21",
          patchedVersion: "4.17.21",
        },
      ],
      reason: "Lockfile already on patched lodash@4.17.21",
      strategy: "override",
      rootPackages: ["lodash"],
      dependencyChains: [],
      packageManager: "npm",
      manifestPath: "package.json",
      createdAt: "2025-01-01T00:00:00.000Z",
      createdBy: "fixture",
      reviewBy: "2026-12-01T00:00:00.000Z",
      reviewReason: "check",
    });
    expect(result.statuses).toContain("REMOVABLE");
    expect(result.removableReason).toBe("already-at-patched");
    expect(result.suggestedAction).toMatch(/leftover override/);
  });

  it("treats ^patched override as covering the advisory when the dep range is already safe", () => {
    const result = classifyEntry(fixtureDir("npm-mixed"), {
      id: "lodash-removable",
      status: "active",
      package: "lodash",
      forcedVersion: "^4.17.21",
      scope: { type: "global" },
      advisories: [
        {
          ghsaId: "GHSA-35jh-r3h4-6jhm",
          severity: "high",
          vulnerableRange: "< 4.17.21",
          patchedVersion: "4.17.21",
        },
      ],
      reason: "range override",
      strategy: "override",
      rootPackages: ["lodash"],
      dependencyChains: [],
      packageManager: "npm",
      manifestPath: "package.json",
      createdAt: "2025-01-01T00:00:00.000Z",
      createdBy: "fixture",
      reviewBy: "2026-12-01T00:00:00.000Z",
      reviewReason: "check",
    });
    expect(result.statuses).not.toContain("DRIFT");
    expect(result.removableReason).toBe("already-at-patched");
  });

  it("does not treat an override floor below the patched version as already-at-patched", () => {
    const result = classifyEntry(fixtureDir("npm-mixed"), {
      id: "lodash-weak",
      status: "active",
      package: "lodash",
      forcedVersion: "^4.17.0",
      scope: { type: "global" },
      advisories: [
        {
          ghsaId: "GHSA-35jh-r3h4-6jhm",
          severity: "high",
          vulnerableRange: "< 4.17.21",
          patchedVersion: "4.17.21",
        },
      ],
      reason: "weak range",
      strategy: "override",
      rootPackages: ["lodash"],
      dependencyChains: [],
      packageManager: "npm",
      manifestPath: "package.json",
      createdAt: "2025-01-01T00:00:00.000Z",
      createdBy: "fixture",
      reviewBy: "2026-12-01T00:00:00.000Z",
      reviewReason: "check",
    });
    expect(result.removableReason).not.toBe("already-at-patched");
  });

  it("treats a weak override as a no-op to raise, not as leftover to drop", () => {
    const result = classifyEntry(fixtureDir("npm-mixed"), {
      id: "qs-weak",
      status: "active",
      package: "qs",
      forcedVersion: "^6.5.0",
      scope: { type: "global" },
      advisories: [
        { ghsaId: "GHSA-qs-high", severity: "high", vulnerableRange: "< 6.11.0", patchedVersion: "6.11.2" },
      ],
      reason: "weak range",
      strategy: "override",
      rootPackages: ["express"],
      dependencyChains: [],
      packageManager: "npm",
      manifestPath: "package.json",
      createdAt: "2025-01-01T00:00:00.000Z",
      createdBy: "fixture",
      reviewBy: "2026-12-01T00:00:00.000Z",
      reviewReason: "check",
    });
    expect(result.statuses).not.toContain("REMOVABLE");
    expect(result.weakOverride).toBe(true);
    expect(result.suggestedAction).toMatch(/fix --apply/);
    expect(result.suggestedAction).toMatch(/no-op/);
  });
});

describe("reconcileWithAudit", () => {
  const base = {
    entry: {
      id: "1",
      status: "active",
      package: "qs",
      forcedVersion: "6.11.2",
      advisories: [{ severity: "high" as const, vulnerableRange: "< 6.11.0" }],
    } as MetadataEntry,
    status: "OK" as const,
    statuses: ["OK" as const],
    suggestedAction: "keep",
    issues: [],
    installedVersions: ["6.10.0"],
  } satisfies CheckEntry;

  it("does not resolve when lockfile is still vulnerable even if audit is silent", () => {
    const next = reconcileWithAudit([base], []);
    expect(next[0]!.status).toBe("OK");
  });

  it("marks RESOLVED when audit is silent and lockfile is already REMOVABLE", () => {
    const next = reconcileWithAudit(
      [{ ...base, status: "REMOVABLE", statuses: ["REMOVABLE"], installedVersions: ["6.11.2"] }],
      [],
    );
    expect(next[0]!.statuses).toContain("RESOLVED");
    expect(next[0]!.removableReason).toBe("audit-clear");
  });

  it("keeps existing reason when already RESOLVED", () => {
    const next = reconcileWithAudit(
      [
        {
          ...base,
          status: "RESOLVED",
          statuses: ["RESOLVED", "REMOVABLE"],
          removableReason: "no-vulnerable-version",
          installedVersions: ["6.11.2"],
        },
      ],
      [],
    );
    expect(next[0]!.removableReason).toBe("no-vulnerable-version");
  });

  it("does not treat a patched lockfile as leftover when parent ranges still allow the vuln", () => {
    const next = reconcileWithAudit(
      [
        {
          ...base,
          entry: {
            ...base.entry,
            package: "picomatch",
            forcedVersion: "^4.0.4",
            advisories: [{ severity: "high", vulnerableRange: "< 4.0.6", patchedVersion: "4.0.6" }],
          },
          installedVersions: ["4.0.7"],
          dependerRanges: ["^4.0.0", "^2.3.1"],
        },
      ],
      [],
    );
    expect(next[0]!.statuses).not.toContain("REMOVABLE");
    expect(next[0]!.status).toBe("OK");
    expect(next[0]!.auditClear).toBe(true);
    expect(next[0]!.suggestedAction).toMatch(/hint/);
    expect(next[0]!.suggestedAction).toMatch(/verify picomatch/);
    expect(next[0]!.suggestedAction).not.toMatch(/will KEEP/);
  });
});

describe("parentRangesAlreadySafe", () => {
  const advisories = [{ severity: "high" as const, vulnerableRange: "< 4.0.6", patchedVersion: "4.0.6" }];

  it("is false when a parent still allows a vulnerable floor", () => {
    expect(parentRangesAlreadySafe(["^4.0.0", "^2.3.1"], advisories)).toBe(false);
  });

  it("is true when every parent already requires the patched floor", () => {
    expect(parentRangesAlreadySafe(["^4.0.7", "4.0.6"], advisories)).toBe(true);
  });
});

describe("toMarkdown removable section", () => {
  it("lists Safe to remove and chains", () => {
    const md = toMarkdown({
      title: "t",
      generatedAt: "now",
      cwd: "/x",
      summary: { removable: 1 },
      entries: [
        {
          entry: {
            id: "1",
            status: "active",
            package: "qs",
            forcedVersion: "6.11.2",
            scope: { type: "global" },
            advisories: [{ ghsaId: "GHSA-qs-high", severity: "high", vulnerableRange: "< 6.11.0" }],
            reason: "r",
            strategy: "override",
            rootPackages: ["express"],
            dependencyChains: ["express@4 → qs@6.11.2"],
            packageManager: "npm",
            manifestPath: "package.json",
            createdAt: "",
            createdBy: "",
            reviewBy: "",
            reviewReason: "",
          },
          status: "RESOLVED",
          statuses: ["RESOLVED", "REMOVABLE"],
          suggestedAction: "drop",
          issues: [],
          removableReason: "no-vulnerable-version",
          roots: ["express"],
          chains: ["express@4 → qs@6.11.2"],
          installedVersions: ["6.11.2"],
        },
      ],
    });
    expect(md).toContain("## Safe to remove");
    expect(md).toContain(removableReasonLabel("no-vulnerable-version"));
    expect(md).toContain("## Dependency chains");
    expect(md).toContain("express@4 → qs@6.11.2");
  });

  it("does not list KEEP results under Safe to remove", () => {
    const md = toMarkdown({
      title: "t",
      generatedAt: "now",
      cwd: "/x",
      summary: {},
      entries: [
        {
          entry: {
            id: "1",
            status: "active",
            package: "picomatch",
            forcedVersion: "^4.0.4",
            scope: { type: "global" },
            advisories: [],
            reason: "r",
            strategy: "override",
            rootPackages: ["a"],
            dependencyChains: [],
            packageManager: "npm",
            manifestPath: "package.json",
            createdAt: "",
            createdBy: "",
            reviewBy: "",
            reviewReason: "",
          },
          status: "OK",
          statuses: ["OK"],
          suggestedAction: "keep",
          issues: [],
          verifyOutcome: "KEEP",
        },
      ],
    });
    expect(md).not.toContain("## Safe to remove");
    expect(md).toContain("KEEP");
  });

  it("lists NEW and OVERDUE before OK", () => {
    const stub = (pkg: string, status: CheckEntry["status"], statuses: CheckEntry["statuses"]): CheckEntry => ({
      entry: {
        id: pkg,
        status: "active",
        package: pkg,
        forcedVersion: "1.0.0",
        scope: { type: "global" },
        advisories: [],
        reason: "",
        strategy: "override",
        rootPackages: [],
        dependencyChains: [],
        packageManager: "npm",
        manifestPath: "package.json",
        createdAt: "",
        createdBy: "",
        reviewBy: "",
        reviewReason: "",
      },
      status,
      statuses,
      suggestedAction: status,
      issues: [],
    });
    const md = toMarkdown({
      title: "t",
      generatedAt: "now",
      cwd: "/x",
      summary: {},
      entries: [stub("ok-pkg", "OK", ["OK"]), stub("new-pkg", "NEW", ["NEW"]), stub("overdue-pkg", "OVERDUE", ["OVERDUE"])],
    });
    const newAt = md.indexOf("new-pkg");
    const overdueAt = md.indexOf("overdue-pkg");
    const okAt = md.indexOf("ok-pkg");
    expect(newAt).toBeGreaterThan(-1);
    expect(newAt).toBeLessThan(overdueAt);
    expect(overdueAt).toBeLessThan(okAt);
  });

  it("names the minimum root version that closes the vuln", () => {
    const md = toMarkdown({
      title: "t",
      generatedAt: "now",
      cwd: "/x",
      summary: {},
      entries: [
        {
          entry: stubEntry("smol-toml", "1.4.2"),
          status: "NEW",
          statuses: ["NEW"],
          suggestedAction: "upgrade",
          issues: [],
          decision: {
            strategy: "upgrade",
            reason: "one root",
            scope: { type: "global" },
            upgradeTargets: [{ name: "nx", from: "23.2.1", to: "23.2.5" }],
          },
          upgradeCommand: "npx nx migrate nx@23.2.5",
        },
      ],
    });
    expect(md).toMatch(/nx@23\.2\.1 → 23\.2\.5/);
  });
});

function stubEntry(pkg: string, forcedVersion: string): MetadataEntry {
  return {
    id: `untracked:${pkg}`,
    status: "active",
    package: pkg,
    forcedVersion,
    scope: { type: "global" },
    advisories: [],
    reason: "imported",
    strategy: "override",
    rootPackages: [],
    dependencyChains: [],
    packageManager: "npm",
    manifestPath: "package.json",
    createdAt: "2025-01-01T00:00:00.000Z",
    createdBy: "init",
    reviewBy: "2026-12-01T00:00:00.000Z",
    reviewReason: "init",
  };
}

describe("classifyUntrackedOverride", () => {
  it("marks an override not in the tree as REMOVABLE", () => {
    const result = classifyUntrackedOverride(fixtureDir("npm-simple"), stubEntry("left-pad", "1.3.0"));
    expect(result.statuses).toContain("REMOVABLE");
    expect(result.removableReason).toBe("not-in-tree");
  });

  it("keeps untracked overrides that roots still pull", () => {
    const result = classifyUntrackedOverride(fixtureDir("npm-simple"), stubEntry("qs", "6.11.2"));
    expect(result.status).toBe("UNTRACKED");
    expect(result.suggestedAction).toMatch(/express/);
  });
});

describe("sortCheckEntries", () => {
  it("puts NEW before OK", () => {
    const mk = (pkg: string, status: CheckEntry["status"]): CheckEntry => ({
      entry: stubEntry(pkg, "1.0.0"),
      status,
      statuses: [status],
      suggestedAction: "",
      issues: [],
    });
    const sorted = sortCheckEntries([mk("z", "OK"), mk("a", "NEW")]);
    expect(sorted.map((e) => e.entry.package)).toEqual(["a", "z"]);
  });
});
