import { describe, expect, it } from "vite-plus/test";
import { highestPatchedVersion, groupAlerts } from "../../src/alerts/dependabot.js";
import {
  recommend,
  stillVulnerable,
  formatUpgradeTarget,
  formatUpgradeTargets,
  resolveUpgradeDecision,
  lookupFromRegistry,
  decide,
  overrideScopes,
  rangeRejectionNote,
} from "../../src/decision/engine.js";
import { DEFAULT_CONFIG } from "../../src/config.js";
import { createOfflineRegistry } from "../../src/registry/verify.js";
import type { Advisory, Decision, DependencyChain } from "../../src/types.js";

describe("decision engine", () => {
  it("recommends upgrade when few roots", () => {
    expect(recommend({ rootCount: 2, threshold: 3, canUpgradeRoots: true })).toBe("upgrade");
  });

  it("pins a non-critical development tree over the threshold by default", () => {
    expect(
      recommend({
        rootCount: 5,
        threshold: 3,
        canUpgradeRoots: true,
        kind: "development",
        severity: "high",
      }),
    ).toBe("override");
  });

  it("waits for a non-critical development tree when pinDevelopment is off", () => {
    expect(
      recommend({
        rootCount: 5,
        threshold: 3,
        canUpgradeRoots: true,
        kind: "development",
        severity: "high",
        pinDevelopment: false,
      }),
    ).toBe("wait");
  });

  it("does not wait for critical, even on a development tree", () => {
    expect(
      recommend({
        rootCount: 5,
        threshold: 3,
        canUpgradeRoots: true,
        kind: "development",
        severity: "critical",
        pinDevelopment: false,
      }),
    ).toBe("override");
  });

  it("pins a high-severity development tree over the threshold by default", () => {
    const decision = decide({
      graph: {
        package: "picomatch",
        versions: ["4.0.2"],
        inTree: true,
        roots: [
          { name: "eslint", version: "8.57.0" },
          { name: "jest", version: "29.0.0" },
          { name: "webpack", version: "5.0.0" },
          { name: "ava", version: "5.0.0" },
        ],
        chains: [],
        dependerRanges: [],
        dependencyKind: "development",
      },
      advisories: [{ severity: "high", vulnerableRange: "< 4.0.4", patchedVersion: "4.0.4" }],
      config: DEFAULT_CONFIG,
    });
    expect(decision.strategy).toBe("override");
    expect(decision.forcedVersion).toBe("4.0.4");
  });

  it("decides wait on a high-severity development tree when pinDevelopment is off", () => {
    const decision = decide({
      graph: {
        package: "picomatch",
        versions: ["4.0.2"],
        inTree: true,
        roots: [
          { name: "eslint", version: "8.57.0" },
          { name: "jest", version: "29.0.0" },
          { name: "webpack", version: "5.0.0" },
          { name: "ava", version: "5.0.0" },
        ],
        chains: [],
        dependerRanges: [],
        dependencyKind: "development",
      },
      advisories: [{ severity: "high", vulnerableRange: "< 4.0.4", patchedVersion: "4.0.4" }],
      config: { ...DEFAULT_CONFIG, pinDevelopment: false },
    });
    expect(decision.strategy).toBe("wait");
    expect(decision.reason).toMatch(/more than the threshold of 3/);
    expect(decision.reason).toMatch(/development dependency/);
    expect(decision.reason).toMatch(/No root upgrade and no pin/);
  });
});

describe("advisory grouping", () => {
  it("merges three hono alerts onto the highest patch", () => {
    const groups = groupAlerts([
      {
        dependency: { package: { name: "hono", ecosystem: "npm" }, manifest_path: "package.json" },
        security_advisory: { ghsa_id: "GHSA-aaa", severity: "high" },
        security_vulnerability: {
          vulnerable_version_range: "< 4.6.5",
          first_patched_version: { identifier: "4.6.5" },
        },
      },
      {
        dependency: { package: { name: "hono", ecosystem: "npm" }, manifest_path: "package.json" },
        security_advisory: { ghsa_id: "GHSA-bbb", severity: "medium" },
        security_vulnerability: {
          vulnerable_version_range: "< 4.7.0",
          first_patched_version: { identifier: "4.7.0" },
        },
      },
      {
        dependency: { package: { name: "hono", ecosystem: "npm" }, manifest_path: "package.json" },
        security_advisory: { ghsa_id: "GHSA-ccc", severity: "high" },
        security_vulnerability: {
          vulnerable_version_range: "< 4.8.1",
          first_patched_version: { identifier: "4.8.1" },
        },
      },
    ]);
    expect(groups).toHaveLength(1);
    expect(groups[0]!.package).toBe("hono");
    expect(groups[0]!.advisories).toHaveLength(3);
    expect(groups[0]!.forcedVersion).toBe("4.8.1");
    expect(highestPatchedVersion(groups[0]!.advisories)).toBe("4.8.1");
  });
});

describe("override scope", () => {
  it("pins each immediate parent instead of one global override", () => {
    expect(
      overrideScopes({
        package: "qs",
        versions: ["6.5.0"],
        inTree: true,
        roots: [{ name: "express", version: "4.18.2" }],
        chains: [
          { path: ["express@4.18.2", "qs@6.5.0"], package: "qs", version: "6.5.0" },
          {
            path: ["express@4.18.2", "body-parser@1.20.1", "qs@6.5.0"],
            package: "qs",
            version: "6.5.0",
          },
        ],
        dependerRanges: [],
      }),
    ).toEqual([
      { type: "scoped", parent: "body-parser" },
      { type: "scoped", parent: "express" },
    ]);
  });

  it("keeps a global pin when the package is a direct dependency", () => {
    expect(
      overrideScopes({
        package: "qs",
        versions: ["6.5.0"],
        inTree: true,
        roots: [{ name: "qs", version: "6.5.0" }],
        chains: [{ path: ["qs@6.5.0"], package: "qs", version: "6.5.0" }],
        dependerRanges: [],
      }),
    ).toEqual([{ type: "global" }]);
  });
});

describe("upgrade targets", () => {
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
    expect(next.reason).toMatch(/already the latest published version/);
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
    expect(next.reason).toMatch(/no published version that closes smol-toml/);
  });

  it("waits instead of overriding when a development-tree upgrade cannot be proven", async () => {
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
    const next = await resolveUpgradeDecision(nxUpgrade("23.2.0"), lookupFromRegistry(registry), {
      ...smolTomlProof("23.2.0"),
      dependencyKind: "development",
      pinDevelopment: false,
    });
    expect(next.strategy).toBe("wait");
    expect(next.reason).toMatch(/no published version that closes smol-toml/);
    expect(next.reason).toMatch(/development dependency, not critical/);
  });

  it("pins a development tree when no published root closes the advisory", async () => {
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
    const next = await resolveUpgradeDecision(nxUpgrade("23.2.0"), lookupFromRegistry(registry), {
      ...smolTomlProof("23.2.0"),
      dependencyKind: "development",
    });
    expect(next.strategy).toBe("override");
    expect(next.reason).toMatch(/Pin smol-toml@1\.4\.2/);
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
    const next = await resolveUpgradeDecision(nxUpgrade("23.2.0"), lookupFromRegistry(registry), {
      vulnPackage: "smol-toml",
      advisories: smolTomlAdvisories,
      chains: [
        {
          path: ["nx@23.2.0", "@nx/js@23.2.0", "smol-toml@1.0.1"],
          package: "smol-toml",
          version: "1.0.1",
        },
      ],
    });
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

  it("installs direct dependencies whose peer range rejects the new root", async () => {
    const next = await resolveUpgradeDecision(
      {
        strategy: "upgrade",
        reason: "few roots",
        forcedVersion: "19.2.14",
        scope: { type: "global" },
        upgradeTargets: [{ name: "@angular/core", from: "19.2.0" }],
      },
      {
        versionsNewerThan: async () => ["19.2.14"],
        peerDependencies: async (pkg, version): Promise<Record<string, string> | undefined> => {
          if (pkg === "@angular/core") return {};
          if (pkg === "@angular/common" && version === "19.2.0") {
            return { "@angular/core": "19.2.0" };
          }
          if (pkg === "@angular/common" && version === "19.2.14") {
            return { "@angular/core": "19.2.14" };
          }
          if (pkg === "@angular/forms") return { "@angular/core": "^19.0.0" };
          return undefined;
        },
      },
      {
        vulnPackage: "@angular/core",
        advisories: [{ severity: "high", vulnerableRange: "< 19.2.14", patchedVersion: "19.2.14" }],
        chains: [{ path: ["@angular/core@19.2.0"], package: "@angular/core", version: "19.2.0" }],
        directs: [
          { name: "@angular/core", version: "19.2.0" },
          { name: "@angular/common", version: "19.2.0" },
          { name: "@angular/forms", version: "19.2.0" },
        ],
      },
    );
    expect(next.upgradeTargets?.map((target) => target.name)).toEqual([
      "@angular/core",
      "@angular/common",
    ]);
    expect(next.upgradeTargets?.[1]).toMatchObject({ from: "19.2.0", to: "19.2.14" });
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

describe("rangeRejectionNote", () => {
  const dependers = [
    { parent: "body-parser", range: "6.5.0", version: "1.20.1" },
    { parent: "express", range: "6.5.0", version: "4.18.2" },
  ];

  it("names the parents a safe version falls outside of and points at the root", () => {
    expect(
      rangeRejectionNote({
        pkg: "qs",
        version: "6.11.2",
        dependers,
        strategy: "upgrade",
        upgradeTargets: [{ name: "express", from: "4.18.2", to: "4.18.3" }],
      }),
    ).toBe(
      "body-parser@1.20.1 and express@4.18.2 ask for qs@6.5.0. That does not include 6.11.2. Upgrade the root first. express@4.18.2 → 4.18.3 moves that range.",
    );
  });

  it("says nothing when every parent range accepts the version", () => {
    expect(
      rangeRejectionNote({
        pkg: "qs",
        version: "6.5.0",
        dependers,
        strategy: "upgrade",
        upgradeTargets: [{ name: "express", from: "4.18.2", to: "4.18.3" }],
      }),
    ).toBeUndefined();
  });

  it("warns that a pin can break the parent that still asks for the old range", () => {
    expect(
      rangeRejectionNote({
        pkg: "qs",
        version: "6.11.2",
        dependers: [{ parent: "body-parser", range: "~6.5.0", version: "1.20.1" }],
        strategy: "override",
      }),
    ).toBe(
      "body-parser@1.20.1 asks for qs@~6.5.0. That does not include 6.11.2. The pin forces qs@6.11.2. That parent can fail to build.",
    );
  });
});

describe("stillVulnerable", () => {
  it("flags uuid@10 against < 11.1.1", () => {
    expect(
      stillVulnerable("10.0.0", [
        { severity: "high", vulnerableRange: "< 11.1.1", patchedVersion: "11.1.1" },
      ]),
    ).toBe(true);
  });

  it("accepts 11.1.1", () => {
    expect(stillVulnerable("11.1.1", [{ severity: "high", vulnerableRange: "< 11.1.1" }])).toBe(
      false,
    );
  });
});
