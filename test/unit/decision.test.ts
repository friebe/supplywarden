import { describe, expect, it } from "vitest";
import { highestPatchedVersion, groupAlerts } from "../../src/alerts/dependabot.js";
import { recommend, stillVulnerable, upgradeTargetTo, formatUpgradeTarget, resolveUpgradeDecision } from "../../src/decision/engine.js";
import { loadAlertFile } from "../../src/alerts/dependabot.js";
import { join } from "node:path";
import { FIXTURES_ROOT } from "../helpers/fixture-project.js";
import { assessImpact } from "../../src/validation/impact-diff.js";
import { DEFAULT_CONFIG } from "../../src/config.js";

describe("decision engine", () => {
  it("recommends upgrade when few roots", () => {
    expect(recommend({ rootCount: 2, threshold: 3, canUpgradeRoots: true })).toBe("upgrade");
  });

  it("recommends override when many roots", () => {
    expect(recommend({ rootCount: 5, threshold: 3, canUpgradeRoots: true })).toBe("override");
  });
});

describe("advisory grouping", () => {
  it("merges three hono alerts onto the highest patch", () => {
    const alerts = loadAlertFile(join(FIXTURES_ROOT, "alerts/hono-triple.json"));
    const groups = groupAlerts(Array.isArray(alerts) ? alerts : [alerts]);
    expect(groups).toHaveLength(1);
    expect(groups[0]!.package).toBe("hono");
    expect(groups[0]!.advisories).toHaveLength(3);
    expect(groups[0]!.forcedVersion).toBe("4.8.1");
    expect(highestPatchedVersion(groups[0]!.advisories)).toBe("4.8.1");
  });

  it("labels a Dependabot development-scoped alert", () => {
    const groups = groupAlerts([
      {
        dependency: {
          package: { name: "picomatch", ecosystem: "npm" },
          manifest_path: "package.json",
          scope: "development",
        },
        security_advisory: { ghsa_id: "GHSA-dev", severity: "high" },
        security_vulnerability: { vulnerable_version_range: "< 4.0.1", first_patched_version: { identifier: "4.0.1" } },
      },
    ]);
    expect(groups[0]!.dependencyKind).toBe("development");
  });

  it("reads Dependabot scopes from alerts/mixed.json", () => {
    const alerts = loadAlertFile(join(FIXTURES_ROOT, "alerts/mixed.json"));
    const groups = groupAlerts(Array.isArray(alerts) ? alerts : [alerts]);
    const byPkg = Object.fromEntries(groups.map((g) => [g.package, g]));
    expect(byPkg.picomatch?.dependencyKind).toBe("development");
    expect(byPkg.qs?.dependencyKind).toBe("production");
    expect(byPkg.qs?.advisories).toHaveLength(2);
    expect(byPkg.ws?.dependencyKind).toBe("production");
  });

  it("treats mixed runtime+development as production", () => {
    const groups = groupAlerts([
      {
        dependency: {
          package: { name: "qs", ecosystem: "npm" },
          manifest_path: "package.json",
          scope: "development",
        },
        security_advisory: { severity: "high" },
        security_vulnerability: { vulnerable_version_range: "< 6.11.0" },
      },
      {
        dependency: {
          package: { name: "qs", ecosystem: "npm" },
          manifest_path: "package.json",
          scope: "runtime",
        },
        security_advisory: { severity: "high" },
        security_vulnerability: { vulnerable_version_range: "< 6.11.0" },
      },
    ]);
    expect(groups).toHaveLength(1);
    expect(groups[0]!.dependencyKind).toBe("production");
  });
});

describe("upgrade targets", () => {
  it("does not suggest the version already installed", () => {
    expect(upgradeTargetTo("23.3.0", "23.3.0", "23.3.0")).toBeUndefined();
    expect(upgradeTargetTo("23.3.0", "23.4.1", "23.4.1")).toBe("23.4.1");
    expect(upgradeTargetTo("23.3.0", undefined, "24.0.0")).toBe("24.0.0");
  });

  it("formats installed vs destination", () => {
    expect(formatUpgradeTarget({ name: "nx", from: "23.3.0", to: "23.4.1" })).toBe(
      "nx@23.3.0 → 23.4.1",
    );
    expect(formatUpgradeTarget({ name: "nx", from: "23.3.0" })).toMatch(/installed 23\.3\.0/);
    expect(formatUpgradeTarget({ name: "nx", from: "23.3.0" })).not.toBe("nx@23.3.0");
  });

  it("falls back to override when the root is already latest", async () => {
    const next = await resolveUpgradeDecision(
      {
        strategy: "upgrade",
        reason: "few roots",
        forcedVersion: "1.2.3",
        scope: { type: "global" },
        upgradeTargets: [{ name: "nx", from: "23.3.0" }],
      },
      {
        latestVersion: async () => "23.3.0",
        getLatestMatching: async () => undefined,
      },
    );
    expect(next.strategy).toBe("override");
    expect(next.reason).toMatch(/already at latest/);
  });

  it("fills to when a newer release exists", async () => {
    const next = await resolveUpgradeDecision(
      {
        strategy: "upgrade",
        reason: "few roots",
        forcedVersion: "1.2.3",
        scope: { type: "global" },
        upgradeTargets: [{ name: "nx", from: "23.3.0" }],
      },
      {
        latestVersion: async () => "23.4.1",
        getLatestMatching: async () => "23.4.1",
      },
    );
    expect(next.strategy).toBe("upgrade");
    expect(next.upgradeTargets?.[0]).toMatchObject({ name: "nx", from: "23.3.0", to: "23.4.1" });
  });
});

describe("stillVulnerable", () => {
  it("flags uuid@10 against < 11.1.1", () => {
    expect(
      stillVulnerable("10.0.0", [{ severity: "high", vulnerableRange: "< 11.1.1", patchedVersion: "11.1.1" }]),
    ).toBe(true);
  });

  it("accepts 11.1.1", () => {
    expect(
      stillVulnerable("11.1.1", [{ severity: "high", vulnerableRange: "< 11.1.1" }]),
    ).toBe(false);
  });
});

describe("impact diff", () => {
  it("blocks above threshold", () => {
    const impact = assessImpact(120, DEFAULT_CONFIG);
    expect(impact.blocked).toBe(true);
    expect(impact.warning).toBe(true);
  });
});
