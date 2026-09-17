import { describe, expect, it } from "vitest";
import { isNxPackage, rootUpgradeCommand } from "../../src/fix/upgrade-command.js";

describe("rootUpgradeCommand", () => {
  it("starts nx migrate for nx and @nx plugins", () => {
    expect(isNxPackage("nx")).toBe(true);
    expect(isNxPackage("@nx/js")).toBe(true);
    expect(isNxPackage("express")).toBe(false);
    expect(rootUpgradeCommand("npm", [{ name: "nx", from: "23.3.0", to: "23.4.1" }])).toEqual({
      file: "npx",
      args: ["nx", "migrate", "nx@23.4.1"],
      display: "npx nx migrate nx@23.4.1",
      kind: "nx",
    });
    expect(rootUpgradeCommand("pnpm", [{ name: "@nx/js", from: "23.3.0", to: "23.4.1" }])?.display).toBe(
      "npx nx migrate nx@23.4.1",
    );
  });

  it("uses the package manager for non-nx roots", () => {
    expect(rootUpgradeCommand("npm", [{ name: "express", from: "4.18.2", to: "4.21.2" }])).toEqual({
      file: "npm",
      args: ["install", "express@4.21.2"],
      display: "npm install express@4.21.2",
      kind: "install",
    });
    expect(rootUpgradeCommand("pnpm", [{ name: "express", from: "4.18.2", to: "4.21.2" }])?.display).toBe(
      "pnpm add express@4.21.2",
    );
  });
});
