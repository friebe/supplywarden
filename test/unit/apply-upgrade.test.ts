import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { existsSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vite-plus/test";
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

async function pnpmRefreshProject(): Promise<string> {
  const dir = await mkdtemp(join(tmpdir(), "supplywarden-refresh-"));
  dirs.push(dir);
  await writeFile(
    join(dir, "package.json"),
    `${JSON.stringify({ name: "app", private: true, dependencies: { express: "^4.18.2" } }, null, 2)}\n`,
  );
  await writeFile(
    join(dir, "pnpm-lock.yaml"),
    `lockfileVersion: '9.0'

importers:
  .:
    dependencies:
      express:
        specifier: ^4.18.2
        version: 4.18.2

packages:
  express@4.18.2: {}
  qs@6.5.0: {}

snapshots:
  express@4.18.2:
    dependencies:
      qs: ^6.0.0
  qs@6.5.0: {}
`,
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
  chains: [{ path: ["nx@23.3.0", "smol-toml@1.3.0"], package: "smol-toml", version: "1.3.0" }],
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
  it("suggests a lockfile refresh without writing an override", async () => {
    const cwd = await nxProject();
    await writeFile(join(cwd, "pnpm-lock.yaml"), "lockfileVersion: '9.0'\n");
    const result = await applyFix({
      cwd,
      config: DEFAULT_CONFIG,
      group: { ...group, package: "zod", forcedVersion: "4.6.6" },
      graph: { ...graph, package: "zod", versions: ["4.6.5"] },
      decision: {
        strategy: "refresh",
        reason: "the parent range accepts the patch",
        forcedVersion: "4.6.6",
        scope: { type: "scoped", parent: "@angular/forms" },
      },
      apply: false,
    });

    expect(result.exitCode).toBe(0);
    expect(result.messages.join("\n")).toMatch(/pnpm update --recursive zod/);
    const pkg = JSON.parse(await readFile(join(cwd, "package.json"), "utf8"));
    expect(pkg.pnpm?.overrides).toBeUndefined();
  });

  it("applies and verifies a pnpm lockfile refresh without writing an override", async () => {
    const cwd = await pnpmRefreshProject();
    const calls: Array<{ file: string; args: string[] }> = [];
    const result = await applyFix({
      cwd,
      config: DEFAULT_CONFIG,
      group: {
        package: "qs",
        manifestPath: "package.json",
        advisories: [{ severity: "high", vulnerableRange: "<6.11.2", patchedVersion: "6.11.2" }],
        maxSeverity: "high",
        forcedVersion: "6.11.2",
        mergedVulnerableRange: "<6.11.2",
      },
      graph: {
        package: "qs",
        versions: ["6.5.0"],
        inTree: true,
        roots: [{ name: "express", version: "4.18.2" }],
        chains: [
          { path: ["express@4.18.2", "qs@6.5.0"], package: "qs", version: "6.5.0" },
        ],
        dependerRanges: ["^6.0.0"],
        dependers: [{ parent: "express", range: "^6.0.0", version: "4.18.2" }],
      },
      decision: {
        strategy: "refresh",
        reason: "the parent range accepts the patch",
        forcedVersion: "6.11.2",
        scope: { type: "scoped", parent: "express" },
      },
      apply: true,
      skipInstall: false,
      audit: {
        async audit() {
          return { vulnerabilities: [] };
        },
      },
      install: {
        async install() {
          return { ok: true };
        },
        async runCommand(_cwd, file, args) {
          calls.push({ file, args });
          const lockPath = join(cwd, "pnpm-lock.yaml");
          const lock = await readFile(lockPath, "utf8");
          await writeFile(lockPath, lock.replaceAll("6.5.0", "6.11.2"));
          return { ok: true };
        },
      },
    });

    expect(result.exitCode).toBe(0);
    expect(calls).toEqual([
      { file: "pnpm", args: ["update", "--recursive", "qs"] },
    ]);
    expect(result.messages.join("\n")).toMatch(/No root upgrade or override was needed/);
    const pkg = JSON.parse(await readFile(join(cwd, "package.json"), "utf8"));
    expect(pkg.pnpm?.overrides).toBeUndefined();
  });

  it("suggests nx migrate and does not run it by default", async () => {
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
    expect(calls).toEqual([]);
    expect(result.messages.join("\n")).toMatch(/npx nx migrate nx@23\.4\.1/);
    expect(result.messages.join("\n")).toMatch(/autoApplyRootUpgrade/);
    const pkg = JSON.parse(await readFile(join(cwd, "package.json"), "utf8"));
    expect(pkg.devDependencies.nx).toBe("^23.3.0");
  });

  it("does not rewrite package.json and prints nx migrate when skipInstall is set", async () => {
    const cwd = await nxProject();
    const result = await applyFix({
      cwd,
      config: { ...DEFAULT_CONFIG, autoApplyRootUpgrade: true },
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

  it("hands off to nx migrate when autoApplyRootUpgrade is on", async () => {
    const cwd = await nxProject();
    const calls: Array<{ file: string; args: string[] }> = [];
    const result = await applyFix({
      cwd,
      config: { ...DEFAULT_CONFIG, autoApplyRootUpgrade: true },
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

  it("suggests npm install for a normal root and runs it when autoApplyRootUpgrade is on", async () => {
    const cwd = await mkdtemp(join(tmpdir(), "supplywarden-upgrade-"));
    dirs.push(cwd);
    await writeFile(
      join(cwd, "package.json"),
      `${JSON.stringify({ name: "app", private: true, dependencies: { express: "^4.18.2" } }, null, 2)}\n`,
    );
    const expressDecision = {
      strategy: "upgrade" as const,
      reason: "one root",
      forcedVersion: "6.11.2",
      scope: { type: "global" as const },
      upgradeTargets: [{ name: "express", from: "4.18.2", to: "4.21.2" }],
    };
    const expressGraph: GraphAnalysis = {
      package: "qs",
      versions: ["6.5.0"],
      inTree: true,
      roots: [{ name: "express", version: "4.18.2", range: "^4.18.2" }],
      chains: [{ path: ["express@4.18.2", "qs@6.5.0"], package: "qs", version: "6.5.0" }],
      dependerRanges: ["6.5.0"],
    };
    const expressGroup: PackageAlertGroup = {
      package: "qs",
      manifestPath: "package.json",
      advisories: [{ severity: "high", vulnerableRange: "< 6.11.2", patchedVersion: "6.11.2" }],
      maxSeverity: "high",
      forcedVersion: "6.11.2",
      mergedVulnerableRange: "< 6.11.2",
    };
    const suggested = await applyFix({
      cwd,
      config: DEFAULT_CONFIG,
      group: expressGroup,
      graph: expressGraph,
      decision: expressDecision,
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
        async runCommand() {
          return { ok: true };
        },
      },
    });
    expect(suggested.exitCode).toBe(0);
    expect(suggested.messages.join("\n")).toMatch(/npm install express@4\.21\.2/);
    expect(suggested.messages.join("\n")).not.toMatch(/nx migrate/);

    const calls: Array<{ file: string; args: string[] }> = [];
    const applied = await applyFix({
      cwd,
      config: { ...DEFAULT_CONFIG, autoApplyRootUpgrade: true },
      group: expressGroup,
      graph: expressGraph,
      decision: expressDecision,
      apply: true,
      skipInstall: false,
      registry: {
        async verifyPackageVersion() {
          return { exists: true, deprecated: null };
        },
      },
      audit: {
        async audit() {
          return { vulnerabilities: [] };
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
    expect(applied.exitCode).toBe(0);
    expect(calls).toEqual([{ file: "npm", args: ["install", "express@4.21.2"] }]);
  });

  it("suggests npm install then nx migrate when both roots are present", async () => {
    const cwd = await nxProject();
    const mixed = {
      ...decision,
      upgradeTargets: [
        { name: "nx", from: "23.3.0", to: "23.4.1" },
        { name: "lodash", from: "4.17.20", to: "4.17.21" },
      ],
    };
    const mixedGraph: GraphAnalysis = {
      ...graph,
      roots: [
        { name: "nx", version: "23.3.0", range: "^23.3.0" },
        { name: "lodash", version: "4.17.20", range: "^4.17.20" },
      ],
      chains: [
        { path: ["nx@23.3.0", "smol-toml@1.3.0"], package: "smol-toml", version: "1.3.0" },
        { path: ["lodash@4.17.20", "smol-toml@1.3.0"], package: "smol-toml", version: "1.3.0" },
      ],
    };
    const suggested = await applyFix({
      cwd,
      config: DEFAULT_CONFIG,
      group,
      graph: mixedGraph,
      decision: mixed,
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
        async runCommand() {
          return { ok: true };
        },
      },
    });
    expect(suggested.exitCode).toBe(0);
    expect(suggested.messages.join("\n")).toMatch(/npm install lodash@4\.17\.21/);
    expect(suggested.messages.join("\n")).toMatch(/npx nx migrate nx@23\.4\.1/);
    expect(suggested.messages.join("\n")).toMatch(/then/);

    const calls: Array<{ file: string; args: string[] }> = [];
    const applied = await applyFix({
      cwd,
      config: { ...DEFAULT_CONFIG, autoApplyRootUpgrade: true },
      group,
      graph: mixedGraph,
      decision: mixed,
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
    expect(applied.exitCode).toBe(0);
    expect(calls).toEqual([
      { file: "npm", args: ["install", "lodash@4.17.21"] },
      { file: "npx", args: ["nx", "migrate", "nx@23.4.1"] },
    ]);
  });

  it("prints triage and does not write an override or a metadata file", async () => {
    const cwd = await nxProject();
    const triageDecision = {
      strategy: "triage" as const,
      reason: "development tree",
      forcedVersion: "1.4.2",
      scope: { type: "global" as const },
    };
    const applied = await applyFix({
      cwd,
      config: DEFAULT_CONFIG,
      group,
      graph,
      decision: triageDecision,
      apply: true,
    });
    expect(applied.exitCode).toBe(0);
    expect(applied.messages.join("\n")).toMatch(/TRIAGE/);
    expect(applied.messages.join("\n")).toMatch(/Proposal:/);
    expect(applied.messages.join("\n")).toMatch(/--apply --force/);
    expect(applied.writtenFiles).toBeUndefined();
    const pkg = JSON.parse(await readFile(join(cwd, "package.json"), "utf8")) as {
      overrides?: unknown;
    };
    expect(pkg.overrides).toBeUndefined();
    expect(existsSync(join(cwd, "security-metadata.json"))).toBe(false);
  });

  it("force-writes the triage proposal when --force is set", async () => {
    const cwd = await nxProject();
    const triageDecision = {
      strategy: "triage" as const,
      reason: "Breaking major pin needs a human decision.",
      forcedVersion: "2.0.0",
      scope: { type: "global" as const },
    };
    const applied = await applyFix({
      cwd,
      config: DEFAULT_CONFIG,
      group: {
        ...group,
        advisories: [
          {
            severity: "high",
            vulnerableRange: "< 2.0.0",
            patchedVersion: "2.0.0",
          },
        ],
        forcedVersion: "2.0.0",
      },
      graph: { ...graph, versions: ["1.4.1"] },
      decision: triageDecision,
      apply: true,
      force: true,
      registry: {
        async verifyPackageVersion() {
          return { exists: true, deprecated: null };
        },
      },
    });
    expect(applied.exitCode).toBe(0);
    expect(applied.messages.join("\n")).toMatch(/FORCED/);
    const pkg = JSON.parse(await readFile(join(cwd, "package.json"), "utf8")) as {
      overrides?: Record<string, string>;
    };
    expect(pkg.overrides?.["smol-toml@>=1 <2.0.0"]).toBe("2.0.0");
  });

  it("explains why a breaking major root upgrade writes no override", async () => {
    const cwd = await nxProject();
    const breaking = {
      ...decision,
      upgradeTargets: [{ name: "nx", from: "23.3.0", to: "24.0.0" }],
    };
    const result = await applyFix({
      cwd,
      config: DEFAULT_CONFIG,
      group,
      graph,
      decision: breaking,
      apply: true,
      skipInstall: false,
      registry: {
        async verifyPackageVersion() {
          return { exists: true, deprecated: null };
        },
      },
    });
    expect(result.exitCode).toBe(0);
    expect(result.messages.join("\n")).toMatch(/No override written/);
    expect(result.messages.join("\n")).toMatch(/breaking major upgrade: nx@23\.3\.0 → 24\.0\.0/);
    expect(result.messages.join("\n")).toMatch(/package\.json was left unchanged/);
    const pkg = JSON.parse(await readFile(join(cwd, "package.json"), "utf8")) as {
      overrides?: unknown;
    };
    expect(pkg.overrides).toBeUndefined();
  });

  it("warns when an override forces the package onto a new major", async () => {
    const cwd = await nxProject();
    const pinDecision = {
      strategy: "override" as const,
      reason: "no proven root upgrade",
      forcedVersion: "2.0.0",
      scope: { type: "global" as const },
    };
    const pinGroup: PackageAlertGroup = {
      ...group,
      package: "left-pad",
      forcedVersion: "2.0.0",
      advisories: [{ severity: "high", vulnerableRange: "< 2.0.0", patchedVersion: "2.0.0" }],
    };
    const pinGraph: GraphAnalysis = {
      ...graph,
      package: "left-pad",
      versions: ["1.3.0"],
    };
    const result = await applyFix({
      cwd,
      config: DEFAULT_CONFIG,
      group: pinGroup,
      graph: pinGraph,
      decision: pinDecision,
      apply: true,
      skipInstall: true,
      registry: {
        async verifyPackageVersion() {
          return { exists: true, deprecated: null };
        },
      },
    });
    expect(result.exitCode).toBe(0);
    expect(result.messages.join("\n")).toMatch(/Breaking major pin: left-pad@1\.3\.0 → 2\.0\.0/);
    const pkg = JSON.parse(await readFile(join(cwd, "package.json"), "utf8")) as {
      overrides?: { "left-pad"?: string };
    };
    expect(pkg.overrides?.["left-pad"]).toBe("2.0.0");
  });

  it("still writes a pin that forces an older major, and only warns", async () => {
    const cwd = await nxProject();
    const pinDecision = {
      strategy: "override" as const,
      reason: "no proven root upgrade",
      forcedVersion: "7.30.1",
      scope: { type: "global" as const },
    };
    const pinGroup: PackageAlertGroup = {
      ...group,
      package: "undici",
      forcedVersion: "7.30.1",
      advisories: [
        { severity: "high", vulnerableRange: ">= 8.0.0 < 8.21.1", patchedVersion: "7.30.1" },
      ],
    };
    const pinGraph: GraphAnalysis = {
      ...graph,
      package: "undici",
      versions: ["8.21.0"],
    };
    const result = await applyFix({
      cwd,
      config: DEFAULT_CONFIG,
      group: pinGroup,
      graph: pinGraph,
      decision: pinDecision,
      apply: true,
      skipInstall: true,
      registry: {
        async verifyPackageVersion() {
          return { exists: true, deprecated: null };
        },
      },
    });
    expect(result.exitCode).toBe(0);
    expect(result.messages.join("\n")).toMatch(
      /Breaking major pin: undici@8\.21\.0 → 7\.30\.1\. Forcing an older major can break\./,
    );
    const pkg = JSON.parse(await readFile(join(cwd, "package.json"), "utf8")) as {
      overrides?: { undici?: string };
    };
    expect(pkg.overrides?.undici).toBe("7.30.1");
  });
});
