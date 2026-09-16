import { describe, expect, it } from "vitest";
import { inferDependencyKind, dependencyKindLabel, mergeDependencyKind } from "../../src/graph/npm.js";

describe("inferDependencyKind", () => {
  it("is development when lockfile copies are all dev", () => {
    expect(
      inferDependencyKind({
        pkgName: "picomatch",
        copies: [{ dev: true }],
        rootNames: ["nx"],
        rootDevDependencies: { nx: "^23.3.0" },
      }),
    ).toBe("development");
  });

  it("is production when a root is a direct runtime dependency", () => {
    expect(
      inferDependencyKind({
        pkgName: "qs",
        copies: [{ dev: true }],
        rootNames: ["express"],
        rootDependencies: { express: "^4.18.2" },
        rootDevDependencies: { nx: "^23.3.0" },
      }),
    ).toBe("production");
  });

  it("is development when every root is only in devDependencies", () => {
    expect(
      inferDependencyKind({
        pkgName: "picomatch",
        copies: [{}],
        rootNames: ["nx"],
        rootDevDependencies: { nx: "^23.3.0" },
      }),
    ).toBe("development");
  });
});

describe("dependencyKindLabel", () => {
  it("only labels development and optional", () => {
    expect(dependencyKindLabel("development")).toBe("development");
    expect(dependencyKindLabel("optional")).toBe("optional");
    expect(dependencyKindLabel("production")).toBe("");
  });

  it("lets production win when merging", () => {
    expect(mergeDependencyKind("development", "production")).toBe("production");
    expect(mergeDependencyKind("development", "development")).toBe("development");
  });
});
