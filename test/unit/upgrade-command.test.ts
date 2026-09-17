import { describe, expect, it } from "vitest";
import { isNxCli, rootUpgradeCommand, rootUpgradeCommands } from "../../src/fix/upgrade-command.js";

describe("rootUpgradeCommand", () => {
  it("uses npm/pnpm/yarn for any non-nx root", () => {
    expect(rootUpgradeCommand("npm", [{ name: "express", from: "4.18.2", to: "4.21.2" }])).toEqual({
      file: "npm",
      args: ["install", "express@4.21.2"],
      display: "npm install express@4.21.2",
      kind: "install",
    });
    expect(rootUpgradeCommand("pnpm", [{ name: "express", from: "4.18.2", to: "4.21.2" }])?.display).toBe(
      "pnpm add express@4.21.2",
    );
    expect(rootUpgradeCommand("yarn", [{ name: "@nx/js", from: "23.3.0", to: "23.4.1" }])).toEqual({
      file: "yarn",
      args: ["add", "@nx/js@23.4.1"],
      display: "yarn add @nx/js@23.4.1",
      kind: "install",
    });
    expect(
      rootUpgradeCommand("npm", [
        { name: "eslint", from: "8.57.0", to: "8.57.1" },
        { name: "picomatch", from: "4.0.2", to: "4.0.4" },
      ])?.display,
    ).toBe("npm install eslint@8.57.1 picomatch@4.0.4");
  });

  it("keeps npm install for lodash when nx is also a root", () => {
    expect(
      rootUpgradeCommands("npm", [
        { name: "nx", from: "23.2.1", to: "23.2.5" },
        { name: "lodash", from: "4.17.20", to: "4.17.21" },
      ]),
    ).toEqual([
      {
        file: "npm",
        args: ["install", "lodash@4.17.21"],
        display: "npm install lodash@4.17.21",
        kind: "install",
      },
      {
        file: "npx",
        args: ["nx", "migrate", "nx@23.2.5"],
        display: "npx nx migrate nx@23.2.5",
        kind: "nx",
      },
    ]);
  });

  it("uses nx migrate only when the root is the nx CLI", () => {
    expect(isNxCli("nx")).toBe(true);
    expect(isNxCli("@nx/js")).toBe(false);
    expect(isNxCli("express")).toBe(false);
    expect(rootUpgradeCommand("npm", [{ name: "nx", from: "23.3.0", to: "23.4.1" }])).toEqual({
      file: "npx",
      args: ["nx", "migrate", "nx@23.4.1"],
      display: "npx nx migrate nx@23.4.1",
      kind: "nx",
    });
  });
});
