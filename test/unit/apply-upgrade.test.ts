import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { applyFix } from "../../src/fix/apply.js";
import { DEFAULT_CONFIG } from "../../src/config.js";
import type { GraphAnalysis, PackageAlertGroup } from "../../src/types.js";

const dirs: string[] = [];

afterEach(async () => {
  await Promise.all(dirs.splice(0).map((dir) => rm(dir, { recursive: true, force: true })));
});

async function nxProject(): Promise<string> {
  const dir = await mkdtemp(join(tmpdir(), "supplywarden-upgrade-"));
  dirs.push(dir);
  await writeFile(
    join(dir, "package.json"),
    `${JSON.stringify(
      {
        name: "nx-app",
        private: true,
        devDependencies: {
          nx: "^23.3.0",
          "@nx/js": "^23.3.0",
          "@nx/angular": "^23.3.0",
        },
      },
      null,
      2,
    )}\n`,
  );
  return dir;
}

const group: PackageAlertGroup = {
  package: "smol-toml",
  manifestPath: "package.json",
  advisories: [{ severity: "high", vulnerableRange: "< 1.4.2", patchedVersion: "1.4.2" }],
  maxSeverity: "high",
  forcedVersion: "1.4.2",
  mergedVulnerableRange: "< 1.4.2",
};

const graph: GraphAnalysis = {
  package: "smol-toml",
  versions: ["1.3.0"],
  inTree: true,
  roots: [{ name: "nx", version: "23.3.0", range: "^23.3.0" }],
  chains: [{ path: ["nx@23.3.0", "smol-toml@1.3.0"] }],
  dependerRanges: ["1.3.0"],
};

const decision = {
  strategy: "upgrade" as const,
  reason: "one root",
  forcedVersion: "1.4.2",
  scope: { type: "global" as const },
  upgradeTargets: [{ name: "nx", from: "23.3.0", to: "23.4.1" }],
};

describe("applyFix root upgrade", () => {
  it("does not rewrite package.json and prints nx migrate when skipInstall is set", async () => {
    const cwd = await nxProject();
    const result = await applyFix({
      cwd,
      config: DEFAULT_CONFIG,
      group,
      graph,
      decision,
      apply: true,
      skipInstall: true,
      registry: {
        async verifyPackageVersion() {
          return { exists: true, deprecated: null };
        },
      },
    });
    expect(result.exitCode).toBe(1);
    expect(result.messages.join("\n")).toMatch(/npx nx migrate nx@23\.4\.1/);
    expect(result.messages.join("\n")).not.toMatch(/@nx\/js@23\.4\.1/);
    const pkg = JSON.parse(await readFile(join(cwd, "package.json"), "utf8"));
    expect(pkg.devDependencies.nx).toBe("^23.3.0");
    expect(pkg.devDependencies["@nx/js"]).toBe("^23.3.0");
  });

  it("hands off to nx migrate instead of editing versions", async () => {
    const cwd = await nxProject();
    const calls: Array<{ file: string; args: string[] }> = [];
    const result = await applyFix({
      cwd,
      config: DEFAULT_CONFIG,
      group,
      graph,
      decision,
      apply: true,
      skipInstall: false,
      registry: {
        async verifyPackageVersion() {
          return { exists: true, deprecated: null };
        },
      },
      install: {
        async install() {
          return { ok: true };
        },
        async runCommand(_cwd, file, args) {
          calls.push({ file, args });
          return { ok: true };
        },
      },
    });
    expect(result.exitCode).toBe(0);
    expect(calls).toEqual([{ file: "npx", args: ["nx", "migrate", "nx@23.4.1"] }]);
    const pkg = JSON.parse(await readFile(join(cwd, "package.json"), "utf8"));
    expect(pkg.devDependencies.nx).toBe("^23.3.0");
    expect(pkg.overrides).toBeUndefined();
    expect(result.messages.join("\n")).toMatch(/Nx owns package selection/);
  });
});
