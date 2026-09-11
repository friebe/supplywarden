import { describe, expect, it } from "vitest";
import { resolvePm } from "../../src/util/pm-exec.js";

const winNode = "C:\\Program Files\\nodejs\\node.exe";

describe("resolvePm", () => {
  it("runs npm via npm-cli.js next to node (avoids Windows .cmd EINVAL)", () => {
    const resolved = resolvePm("npm", {
      platform: "win32",
      execPath: winNode,
      exists: (p) => p.replace(/\\/g, "/").endsWith("node_modules/npm/bin/npm-cli.js"),
    });
    expect(resolved.file).toBe(winNode);
    expect(resolved.argsPrefix[0]?.replace(/\\/g, "/")).toMatch(/node_modules\/npm\/bin\/npm-cli\.js$/);
    expect(resolved.shell).toBe(false);
  });

  it("falls back to npm.cmd with shell on Windows when npm-cli.js is missing", () => {
    const resolved = resolvePm("npm", {
      platform: "win32",
      execPath: winNode,
      exists: () => false,
    });
    expect(resolved.file).toBe("npm.cmd");
    expect(resolved.argsPrefix).toEqual([]);
    expect(resolved.shell).toBe(true);
  });

  it("runs pnpm through corepack when present", () => {
    const resolved = resolvePm("pnpm", {
      platform: "win32",
      execPath: winNode,
      exists: (p) => p.replace(/\\/g, "/").includes("corepack/dist/corepack.js"),
    });
    expect(resolved.file).toBe(winNode);
    expect(resolved.argsPrefix[0]?.replace(/\\/g, "/")).toMatch(/corepack\.js$/);
    expect(resolved.argsPrefix[1]).toBe("pnpm");
    expect(resolved.shell).toBe(false);
  });

  it("uses npm without shell on POSIX", () => {
    const resolved = resolvePm("npm", {
      platform: "linux",
      execPath: "/usr/bin/node",
      exists: () => false,
    });
    expect(resolved.file).toBe("npm");
    expect(resolved.shell).toBe(false);
  });
});
