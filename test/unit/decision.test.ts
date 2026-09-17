import { describe, expect, it } from "vitest";
import { highestPatchedVersion, groupAlerts } from "../../src/alerts/dependabot.js";
import { recommend, stillVulnerable, upgradeTargetTo, formatUpgradeTarget, formatUpgradeTargets, resolveUpgradeDecision, lookupFromRegistry } from "../../src/decision/engine.js";
import { loadAlertFile } from "../../src/alerts/dependabot.js";
import { join } from "node:path";
import { FIXTURES_ROOT } from "../helpers/fixture-project.js";
import { assessImpact } from "../../src/validation/impact-diff.js";
import { DEFAULT_CONFIG } from "../../src/config.js";
import { createOfflineRegistry } from "../../src/registry/verify.js";
import type { Advisory, Decision, DependencyChain } from "../../src/types.js";

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
    expect(
      formatUpgradeTargets({
        strategy: "upgrade",
        reason: "",
        scope: { type: "global" },
        upgradeTargets: [{ name: "nx", from: "23.2.1", to: "23.2.5" }],
      }),
    ).toBe("nx@23.2.1 → 23.2.5");
    expect(
      formatUpgradeTarget({
        name: "nx",
        from: "23.2.0",
        to: "23.2.5",
        skipped: ["23.2.1", "23.2.2"],
      }),
    ).toBe("nx@23.2.0 → 23.2.5 (not 23.2.1, 23.2.2 — still vulnerable)");
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

  it("fills to when a newer release is proven to close the advisory", async () => {
    const next = await resolveUpgradeDecision(
      {
        strategy: "upgrade",
        reason: "few roots",
        forcedVersion: "1.4.2",
        scope: { type: "global" },
        upgradeTargets: [{ name: "nx", from: "23.3.0" }],
      },
      {
        latestVersion: async () => "23.4.1",
        getLatestMatching: async () => "23.4.1",
        dependencyRange: async (pkg, version, dep) => {
          if (pkg === "nx" && dep === "smol-toml" && version === "23.4.1") return "^1.4.2";
          return "^1.3.0";
        },
      },
      smolTomlProof("23.3.0"),
    );
    expect(next.strategy).toBe("upgrade");
    expect(next.upgradeTargets?.[0]).toMatchObject({ name: "nx", from: "23.3.0", to: "23.4.1" });
  });

  it("skips a next patch that still allows the vuln (nx 23.2.1 / smol-toml)", async () => {
    const registry = createOfflineRegistry(
      {
        nx: ["23.2.0", "23.2.1", "23.3.0"],
        "smol-toml": ["1.3.1", "1.4.2"],
      },
      {
        nx: {
          "23.2.1": { "smol-toml": "^1.3.1" },
          "23.3.0": { "smol-toml": "^1.4.2" },
        },
      },
    );
    const next = await resolveUpgradeDecision(
      nxUpgrade("23.2.0"),
      lookupFromRegistry(registry),
      smolTomlProof("23.2.0"),
    );
    expect(next.strategy).toBe("upgrade");
    expect(next.upgradeTargets?.[0]).toMatchObject({ name: "nx", from: "23.2.0", to: "23.3.0" });
    expect(next.upgradeTargets?.[0]?.skipped).toEqual(["23.2.1"]);
  });

  it("falls back to override when no published root version closes the vuln", async () => {
    const registry = createOfflineRegistry(
      {
        nx: ["23.2.0", "23.2.1"],
        "smol-toml": ["1.3.1", "1.4.2"],
      },
      {
        nx: {
          "23.2.1": { "smol-toml": "^1.3.1" },
        },
      },
    );
    const next = await resolveUpgradeDecision(
      nxUpgrade("23.2.0"),
      lookupFromRegistry(registry),
      smolTomlProof("23.2.0"),
    );
    expect(next.strategy).toBe("override");
    expect(next.forcedVersion).toBe("1.4.2");
    expect(next.reason).toMatch(/no proven version that closes smol-toml/);
  });

  it("walks an intermediate hop before judging the vuln package", async () => {
    const registry = createOfflineRegistry(
      {
        nx: ["23.2.0", "23.2.1", "23.3.0"],
        "@nx/js": ["23.2.1", "23.3.0"],
        "smol-toml": ["1.0.1", "1.4.2"],
      },
      {
        nx: {
          "23.2.1": { "@nx/js": "23.2.1" },
          "23.3.0": { "@nx/js": "23.3.0" },
        },
        "@nx/js": {
          "23.2.1": { "smol-toml": "^1.0.1" },
          "23.3.0": { "smol-toml": "^1.4.2" },
        },
      },
    );
    const next = await resolveUpgradeDecision(
      nxUpgrade("23.2.0"),
      lookupFromRegistry(registry),
      {
        vulnPackage: "smol-toml",
        advisories: smolTomlAdvisories,
        chains: [
          {
            path: ["nx@23.2.0", "@nx/js@23.2.0", "smol-toml@1.0.1"],
            package: "smol-toml",
            version: "1.0.1",
          },
        ],
      },
    );
    expect(next.strategy).toBe("upgrade");
    expect(next.upgradeTargets?.[0]?.to).toBe("23.3.0");
  });

  it("upgrades the vuln package itself to the first safe version", async () => {
    const next = await resolveUpgradeDecision(
      {
        strategy: "upgrade",
        reason: "few roots",
        forcedVersion: "6.11.2",
        scope: { type: "global" },
        upgradeTargets: [{ name: "qs", from: "6.5.0" }],
      },
      {
        versionsNewerThan: async () => ["6.5.1", "6.11.2"],
      },
      {
        vulnPackage: "qs",
        advisories: [{ severity: "high", vulnerableRange: "< 6.11.2", patchedVersion: "6.11.2" }],
        chains: [{ path: ["qs@6.5.0"], package: "qs", version: "6.5.0" }],
      },
    );
    expect(next.strategy).toBe("upgrade");
    expect(next.upgradeTargets?.[0]).toMatchObject({ name: "qs", from: "6.5.0", to: "6.11.2" });
  });
});

const smolTomlAdvisories: Advisory[] = [
  { severity: "high", vulnerableRange: "< 1.4.2", patchedVersion: "1.4.2" },
];

function smolTomlProof(installed: string): {
  vulnPackage: string;
  advisories: Advisory[];
  chains: DependencyChain[];
} {
  return {
    vulnPackage: "smol-toml",
    advisories: smolTomlAdvisories,
    chains: [
      {
        path: [`nx@${installed}`, "smol-toml@1.3.1"],
        package: "smol-toml",
        version: "1.3.1",
      },
    ],
  };
}

function nxUpgrade(from: string): Decision {
  return {
    strategy: "upgrade",
    reason: "few roots",
    forcedVersion: "1.4.2",
    scope: { type: "global" },
    upgradeTargets: [{ name: "nx", from }],
  };
}

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
