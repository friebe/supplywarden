import { describe, expect, it } from "vitest";
import { inferSafeFloorFromVulnerableRange } from "../../src/util/vuln-range.js";
import { firstSafeForcedVersion } from "../../src/decision/engine.js";

describe("inferSafeFloorFromVulnerableRange", () => {
  it("reads exclusive and inclusive upper bounds", () => {
    expect(inferSafeFloorFromVulnerableRange("< 4.0.8")).toBe("4.0.8");
    expect(inferSafeFloorFromVulnerableRange("<=4.0.7")).toBe("4.0.8");
    expect(inferSafeFloorFromVulnerableRange(">=4.0.0 <4.0.8 || <2.3.2")).toBe("4.0.8");
  });
});

describe("firstSafeForcedVersion", () => {
  it("raises a patchedVersion that still matches the range", () => {
    expect(
      firstSafeForcedVersion([
        { severity: "high", vulnerableRange: "< 11.1.1", patchedVersion: "10.0.0" },
      ]),
    ).toBe("11.1.1");
  });

  it("keeps a patchedVersion that already closes the range", () => {
    expect(
      firstSafeForcedVersion([
        { severity: "high", vulnerableRange: "< 6.11.0", patchedVersion: "6.11.2" },
      ]),
    ).toBe("6.11.2");
  });
});
