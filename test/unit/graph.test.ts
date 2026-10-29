import { describe, expect, it } from "vite-plus/test";
import {
  inferDependencyKind,
  dependencyKindLabel,
  mergeDependencyKind,
  analyzeNpmGraph,
} from "../../src/graph/npm.js";
import { parsePnpmKey } from "../../src/graph/pnpm.js";
import { extraSnapshotFiles, findPnpmRoot } from "../../src/graph/workspace.js";
import { parseYarnDescriptor } from "../../src/graph/yarn.js";
import { fixtureDir, FIXTURES_ROOT } from "../helpers/fixture-project.js";
import { join } from "node:path";

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

describe("analyzeNpmGraph lockfile dispatch", () => {
  it("reads express → qs from package-lock.json", () => {
    const graph = analyzeNpmGraph(fixtureDir("npm-simple"), "qs");
    expect(graph.inTree).toBe(true);
    expect(graph.versions).toContain("6.5.0");
    expect(graph.roots.map((r) => r.name)).toContain("express");
    expect(graph.chains.some((c) => c.path.join(" → ").includes("express@4.18.2"))).toBe(true);
    expect(graph.dependers).toEqual([
      { parent: "body-parser", range: "6.5.0", version: "1.20.1" },
      { parent: "express", range: "6.5.0", version: "4.18.2" },
    ]);
  });

  it("reads express → qs from pnpm-lock.yaml", () => {
    const graph = analyzeNpmGraph(fixtureDir("pnpm-simple"), "qs");
    expect(graph.inTree).toBe(true);
    expect(graph.versions).toEqual(["6.5.0"]);
    expect(graph.roots).toEqual([{ name: "express", version: "4.18.2", range: "^4.18.2" }]);
    expect(graph.dependencyKind).toBe("production");
    expect(graph.dependers).toEqual([
      { parent: "body-parser", range: "6.5.0", version: "1.20.1" },
      { parent: "express", range: "6.5.0", version: "4.18.2" },
    ]);
    expect(graph.chains.map((c) => c.path)).toEqual(
      expect.arrayContaining([
        ["express@4.18.2", "qs@6.5.0"],
        ["express@4.18.2", "body-parser@1.20.1", "qs@6.5.0"],
      ]),
    );
  });

  it("reads express → qs from Yarn Berry lockfile", () => {
    const graph = analyzeNpmGraph(fixtureDir("yarn-berry-simple"), "qs");
    expect(graph.inTree).toBe(true);
    expect(graph.roots.map((r) => r.name)).toContain("express");
    expect(graph.versions).toContain("6.5.0");
  });

  it("walks this repo's pnpm-lock.yaml", () => {
    const graph = analyzeNpmGraph(join(FIXTURES_ROOT, ".."), "commander");
    expect(graph.inTree).toBe(true);
    expect(graph.roots.some((r) => r.name === "commander")).toBe(true);
  });

  it("keeps the workspace importer and the catalog when the lockfile is above the member", () => {
    const member = join(fixtureDir("pnpm-workspace"), "apps/web");
    expect(findPnpmRoot(member)).toBe(fixtureDir("pnpm-workspace"));
    expect(findPnpmRoot(fixtureDir("npm-simple"))).toBeUndefined();
    expect(findPnpmRoot(fixtureDir("pnpm-simple"))).toBe(fixtureDir("pnpm-simple"));

    const leftPad = analyzeNpmGraph(member, "left-pad");
    expect(leftPad.roots).toEqual([
      { name: "left-pad", version: "1.0.0", range: "1.0.0", importer: "web" },
    ]);

    const minimist = analyzeNpmGraph(member, "minimist");
    expect(minimist.roots).toEqual([
      {
        name: "minimist",
        version: "1.2.0",
        range: "^1.2.0",
        importer: "@repo/ui",
        catalog: "default",
      },
    ]);

    const ms = analyzeNpmGraph(member, "ms");
    expect(ms.roots).toEqual([
      { name: "ms", version: "2.0.0", range: "2.0.0", importer: "@repo/ui" },
    ]);
    expect(extraSnapshotFiles(fixtureDir("pnpm-workspace")).sort()).toEqual([
      "apps/web/package.json",
      "packages/ui/package.json",
      "pnpm-workspace.yaml",
    ]);
  });

  it("does not invent a tree when the package is missing from a pnpm lockfile", () => {
    const graph = analyzeNpmGraph(fixtureDir("pnpm-simple"), "left-pad");
    expect(graph.inTree).toBe(false);
    expect(graph.roots).toEqual([]);
  });
});

describe("lockfile key parsing", () => {
  it("parses pnpm v9 and peer-suffixed keys", () => {
    expect(parsePnpmKey("qs@6.5.0")).toEqual({ name: "qs", version: "6.5.0" });
    expect(parsePnpmKey("/express@4.18.2")).toEqual({ name: "express", version: "4.18.2" });
    expect(parsePnpmKey("fdir@6.5.0(picomatch@4.0.7)")).toEqual({ name: "fdir", version: "6.5.0" });
    expect(parsePnpmKey("@scope/pkg@1.2.3")).toEqual({ name: "@scope/pkg", version: "1.2.3" });
  });

  it("parses yarn descriptors", () => {
    expect(parseYarnDescriptor("express@^4.18.2")).toEqual({ name: "express", range: "^4.18.2" });
    expect(parseYarnDescriptor("express@npm:^4.18.2")).toEqual({
      name: "express",
      range: "^4.18.2",
    });
    expect(parseYarnDescriptor("@scope/pkg@npm:1.0.0")).toEqual({
      name: "@scope/pkg",
      range: "1.0.0",
    });
  });
});
