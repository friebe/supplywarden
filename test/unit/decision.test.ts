import { describe, expect, it } from "vitest";
import { highestPatchedVersion, groupAlerts } from "../../src/alerts/dependabot.js";
import { recommend, stillVulnerable } from "../../src/decision/engine.js";
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
