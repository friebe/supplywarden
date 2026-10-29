import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vite-plus/test";
import { detectPackageManager } from "../../src/graph/npm.js";
import { readPackageJson, writeOverrides } from "../../src/metadata/sync.js";

const pins = [{ package: "qs", version: "1.2.3", scope: { type: "global" as const } }];

async function withDir(files: Record<string, string>, fn: (dir: string) => Promise<void>) {
  const dir = await mkdtemp(join(tmpdir(), "sw-pm-"));
  try {
    for (const [name, body] of Object.entries(files)) {
      await writeFile(join(dir, name), body);
    }
    await fn(dir);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
}

describe("detectPackageManager", () => {
  it("prefers package.json packageManager over a leftover pnpm lockfile", async () => {
    await withDir(
      {
        "package.json": JSON.stringify({ name: "app", packageManager: "npm@10.8.2" }),
        "pnpm-lock.yaml": "lockfileVersion: '9.0'\n",
        "package-lock.json": JSON.stringify({ lockfileVersion: 3, packages: {} }),
      },
      async (dir) => {
        expect(detectPackageManager(dir)).toBe("npm");
      },
    );
  });

  it("uses pnpm-lock.yaml when that is the only signal", async () => {
    await withDir(
      {
        "package.json": JSON.stringify({ name: "app" }),
        "pnpm-lock.yaml": "lockfileVersion: '9.0'\n",
      },
      async (dir) => {
        expect(detectPackageManager(dir)).toBe("pnpm");
      },
    );
  });
});

describe("writeOverrides", () => {
  it("writes npm overrides only, and strips leftover pnpm.overrides", async () => {
    await withDir(
      {
        "package.json": JSON.stringify({
          name: "app",
          pnpm: { overrides: { lodash: "4.17.21" } },
        }),
        "package-lock.json": JSON.stringify({ lockfileVersion: 3, packages: {} }),
      },
      async (dir) => {
        writeOverrides(dir, pins);
        const pkg = readPackageJson(dir);
        expect(pkg.overrides).toEqual({ qs: "1.2.3" });
        expect(pkg.pnpm?.overrides).toBeUndefined();
      },
    );
  });

  it("writes pnpm.overrides only when the lockfile is pnpm", async () => {
    await withDir(
      {
        "package.json": JSON.stringify({ name: "app", overrides: { old: "1.0.0" } }),
        "pnpm-lock.yaml": "lockfileVersion: '9.0'\n",
      },
      async (dir) => {
        writeOverrides(dir, pins);
        const pkg = readPackageJson(dir);
        expect(pkg.overrides).toBeUndefined();
        expect(pkg.pnpm?.overrides).toEqual({ qs: "1.2.3" });
      },
    );
  });

  it("writes yarn resolutions only", async () => {
    await withDir(
      {
        "package.json": JSON.stringify({ name: "app" }),
        "yarn.lock": "# yarn\n",
      },
      async (dir) => {
        writeOverrides(dir, pins);
        const pkg = readPackageJson(dir);
        expect(pkg.overrides).toBeUndefined();
        expect(pkg.pnpm).toBeUndefined();
        expect(pkg.resolutions).toEqual({ qs: "1.2.3" });
      },
    );
  });
});
