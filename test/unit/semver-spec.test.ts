import { describe, expect, it } from "vitest";
import { specAtLeast, specFloorSafe, specMinVersion, versionSatisfiesSpec } from "../../src/util/semver-spec.js";

const qsHigh = [{ severity: "high" as const, vulnerableRange: "< 6.11.0", patchedVersion: "6.11.2" }];

describe("semver spec vs advisory floor", () => {
  it("reads the floor of a caret range", () => {
    expect(specMinVersion("^6.11.2")).toBe("6.11.2");
    expect(specMinVersion(">=6.13.0")).toBe("6.13.0");
  });

  it("treats ^patched and newer floors as covering the advisory", () => {
    expect(specFloorSafe("^6.11.2", qsHigh)).toBe(true);
    expect(specFloorSafe("6.13.0", qsHigh)).toBe(true);
    expect(specAtLeast("^6.13.0", "6.11.2")).toBe(true);
  });

  it("treats a floor below the patched version as not covering", () => {
    expect(specFloorSafe("^6.5.0", qsHigh)).toBe(false);
    expect(specAtLeast("^6.5.0", "6.11.2")).toBe(false);
  });

  it("matches an installed version against a range override", () => {
    expect(versionSatisfiesSpec("6.11.2", "^6.11.2")).toBe(true);
    expect(versionSatisfiesSpec("6.5.0", "^6.11.2")).toBe(false);
  });
});
