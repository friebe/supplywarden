import { existsSync } from "node:fs";
import { writeFile } from "node:fs/promises";
import { join } from "node:path";
import { describe, expect, it } from "vite-plus/test";
import { createStaticAudit } from "../../src/audit/client.js";
import { createLiveRegistry } from "../../src/registry/verify.js";
import { runCheck } from "../../src/commands/check.js";
import { runDoctor } from "../../src/commands/doctor.js";
import { runFix } from "../../src/commands/fix.js";
import { runWhy } from "../../src/commands/why.js";
import { renderHtml } from "../../src/report/html.js";
import { toMarkdown } from "../../src/report/model.js";
import { extractExistingOverrides, readPackageJson } from "../../src/metadata/sync.js";
import { fixtureDir, withFixture } from "../helpers/fixture-project.js";

const qs = {
  package: "qs",
  severity: "high" as const,
  range: "< 6.11.0",
  ghsaId: "GHSA-qs-high",
  patchedVersion: "6.11.2",
};

describe("check", () => {
  it("shows the root and a next command, and writes no metadata file", async () => {
    await withFixture("npm-simple", async (cwd) => {
      const result = await runCheck({
        cwd,
        audit: createStaticAudit([qs]),
        registry: {
          async verifyPackageVersion() {
            return { exists: true, deprecated: null };
          },
        },
      });
      const row = result.report.entries.find((e) => e.package === "qs");
      expect(row?.roots.join(" ")).toMatch(/express/);
      expect(
        row?.trails?.some((trail) => trail.path.includes("express@4.18.2") && trail.range),
      ).toBe(true);
      expect(row?.commands.length).toBeGreaterThan(0);
      expect(result.messages[0]).toMatch(/^qs, high, via express@/);
      expect(toMarkdown(result.report)).toMatch(/express/);
      expect(existsSync(join(cwd, "security-metadata.json"))).toBe(false);
      expect(result.writtenFiles).toBeUndefined();
    });
  });

  it("strict exits 1 when a finding still needs a command", async () => {
    const result = await runCheck({
      cwd: fixtureDir("npm-simple"),
      strict: true,
      audit: createStaticAudit([qs]),
      registry: {
        async verifyPackageVersion() {
          return { exists: true, deprecated: null };
        },
      },
    });
    expect(result.exitCode).toBe(1);
  });
});

describe("why / fix", () => {
  it("finds express as root for qs", () => {
    const result = runWhy({ cwd: fixtureDir("npm-simple"), package: "qs" });
    expect(result.exitCode).toBe(0);
    expect(result.messages.join("\n")).toMatch(/express/);
  });

  it("finds express as root for qs in a pnpm lockfile", () => {
    const result = runWhy({ cwd: fixtureDir("pnpm-simple"), package: "qs" });
    expect(result.exitCode).toBe(0);
    expect(result.messages.join("\n")).toMatch(/express/);
  });

  it("finds express as root for qs in a yarn lockfile", () => {
    const result = runWhy({ cwd: fixtureDir("yarn-simple"), package: "qs" });
    expect(result.exitCode).toBe(0);
    expect(result.messages.join("\n")).toMatch(/express/);
  });

  it("labels picomatch as development-only in npm-mixed", () => {
    const result = runWhy({ cwd: fixtureDir("npm-mixed"), package: "picomatch" });
    expect(result.exitCode).toBe(0);
    expect(result.messages.join("\n")).toMatch(/Tree: development only/);
    expect(result.messages.join("\n")).toMatch(/eslint/);
  });

  it("plans a qs fix from a static audit", async () => {
    const result = await runFix({
      cwd: fixtureDir("npm-simple"),
      apply: false,
      audit: createStaticAudit([qs]),
    });
    expect(result.report.decision?.forcedVersion).toBe("6.11.2");
    expect(result.report.groups?.[0]?.package).toBe("qs");
  });

  it("keeps installed pins when the audit is silent and only drops unused overrides", async () => {
    const result = await runCheck({
      cwd: fixtureDir("npm-mixed"),
      audit: createStaticAudit([]),
    });
    const byPkg = Object.fromEntries(result.report.entries.map((e) => [e.package, e.action]));
    expect(byPkg.qs).toBe("keep");
    expect(byPkg["follow-redirects"]).toBe("keep");
    expect(byPkg.lodash).toBe("drop");
    expect(byPkg.request).toBe("drop");
    expect(result.report.entries.some((e) => e.action !== "drop")).toBe(true);
  });

  it("upgrades a root together with the direct dependency that peers on it", async () => {
    const cwd = fixtureDir("npm-mixed");
    const result = await runCheck({
      cwd,
      audit: createStaticAudit([
        {
          package: "left-pad",
          severity: "high",
          range: "< 1.3.0",
          patchedVersion: "1.3.0",
        },
      ]),
      registry: createLiveRegistry(cwd),
    });
    const row = result.report.entries.find((entry) => entry.package === "left-pad");
    expect(row?.action).toBe("upgrade");
    expect(row?.commands.join("\n")).toBe("npm install @demo/core@1.2.0 @demo/common@1.2.0");
  });

  it("pins under the parent when no published root closes the advisory", async () => {
    const cwd = fixtureDir("npm-mixed");
    const result = await runCheck({
      cwd,
      audit: createStaticAudit([
        {
          package: "marked",
          severity: "high",
          range: "< 4.0.0",
          patchedVersion: "4.0.0",
        },
      ]),
      registry: createLiveRegistry(cwd),
    });
    const row = result.report.entries.find((entry) => entry.package === "marked");
    expect(row?.action).toBe("override");
    expect(row?.summary).toMatch(/under old-tool/);
    expect(row?.summary).toMatch(/old-tool@1\.0\.0 asks for marked@1\.0\.0/);
    expect(row?.summary).toMatch(/That parent can fail to build/);
    expect(row?.commands).toEqual(["supplywarden fix marked --apply"]);
  });

  it("tells you to upgrade the root when the safe version is outside the installed range", async () => {
    const result = await runCheck({
      cwd: fixtureDir("npm-simple"),
      audit: createStaticAudit([qs]),
      registry: {
        async verifyPackageVersion() {
          return { exists: true, deprecated: null };
        },
        async versionsNewerThan(pkg: string) {
          return pkg === "express" ? ["4.18.3"] : [];
        },
        async dependencyRange(pkg: string, version: string, dep: string) {
          if (pkg === "express" && version === "4.18.3" && dep === "qs") return "6.11.2";
          return undefined;
        },
        async peerDependencies() {
          return {};
        },
      },
    });
    const row = result.report.entries.find((entry) => entry.package === "qs");
    expect(row?.action).toBe("upgrade");
    expect(row?.commands).toEqual(["npm install express@4.18.3"]);
    expect(row?.summary).toMatch(/body-parser@1\.20\.1 and express@4\.18\.2 ask for qs@6\.5\.0/);
    expect(row?.summary).toMatch(/Upgrade the root first\. express@4\.18\.2 → 4\.18\.3/);
  });

  it("updates Angular core and common together and leaves forms out", async () => {
    const cwd = fixtureDir("npm-migrations");
    const result = await runCheck({
      cwd,
      audit: createStaticAudit([
        {
          package: "left-pad",
          severity: "high",
          range: "< 1.3.0",
          patchedVersion: "1.3.0",
        },
      ]),
      registry: createLiveRegistry(cwd),
    });
    const row = result.report.entries.find((entry) => entry.package === "left-pad");
    expect(row?.action).toBe("upgrade");
    expect(row?.commands).toEqual(["npx ng update @angular/core@19.2.14 @angular/common@19.2.14"]);
    expect(row?.summary).toMatch(/together, not one package at a time/);
    expect(row?.summary).not.toMatch(/@angular\/forms/);
    expect(row?.upgradeTargets?.map((target) => target.name)).toEqual([
      "@angular/core",
      "@angular/common",
    ]);
  });

  it("shows nx migrate instead of npm install", async () => {
    const cwd = fixtureDir("npm-migrations");
    const result = await runCheck({
      cwd,
      audit: createStaticAudit([
        {
          package: "smol-toml",
          severity: "high",
          range: "< 1.4.2",
          patchedVersion: "1.4.2",
        },
      ]),
      registry: createLiveRegistry(cwd),
    });
    const row = result.report.entries.find((entry) => entry.package === "smol-toml");
    expect(row?.action).toBe("upgrade");
    expect(row?.commands).toEqual(["npx nx migrate nx@23.2.5"]);
  });

  it("updates Storybook with one upgrade command and leaves a loose peer out", async () => {
    const cwd = fixtureDir("npm-migrations");
    const result = await runCheck({
      cwd,
      audit: createStaticAudit([
        {
          package: "braces",
          severity: "high",
          range: "< 3.0.2",
          patchedVersion: "3.0.2",
        },
      ]),
      registry: createLiveRegistry(cwd),
    });
    const row = result.report.entries.find((entry) => entry.package === "braces");
    expect(row?.action).toBe("upgrade");
    expect(row?.commands).toEqual(["npx storybook@8.6.0 upgrade"]);
    expect(row?.summary).toMatch(/together, not one package at a time/);
    expect(row?.upgradeTargets?.map((target) => target.name)).toEqual([
      "storybook",
      "@storybook/react",
    ]);
  });

  it("writes only the named package", async () => {
    await withFixture("npm-simple", async (dir) => {
      await writeFile(
        join(dir, ".supplywardenrc.json"),
        JSON.stringify({ upgradeRootThreshold: 0 }),
      );
      const result = await runFix({
        cwd: dir,
        package: "qs",
        audit: createStaticAudit([
          qs,
          {
            package: "left-pad",
            severity: "high",
            range: "< 1.3.0",
            ghsaId: "GHSA-left-pad",
            patchedVersion: "1.3.0",
          },
        ]),
        apply: true,
        skipInstall: true,
        registry: {
          async verifyPackageVersion() {
            return { exists: true, deprecated: null };
          },
        },
      });
      expect(result.exitCode).toBe(0);
      const written = extractExistingOverrides(readPackageJson(dir)).map((pin) => pin.package);
      expect(written).toContain("qs");
      expect(written).not.toContain("left-pad");
      expect(result.messages.join("\n")).not.toMatch(/left-pad/);
    });
  });

  it("refuses a package the audit does not list", async () => {
    const result = await runFix({
      cwd: fixtureDir("npm-simple"),
      package: "left-pad",
      audit: createStaticAudit([qs]),
      apply: false,
      skipInstall: true,
    });
    expect(result.exitCode).toBe(1);
    expect(result.messages.join("\n")).toMatch(/left-pad is not in this audit/);
  });
});

describe("validation gates", () => {
  it("writes a safe override when the patched version is still inside the range", async () => {
    await withFixture("npm-still-vulnerable", async (dir) => {
      await writeFile(
        join(dir, ".supplywardenrc.json"),
        JSON.stringify({ upgradeRootThreshold: 0 }),
      );
      const result = await runFix({
        cwd: dir,
        audit: createStaticAudit([
          {
            package: "uuid",
            severity: "high",
            range: "< 11.1.1",
            ghsaId: "GHSA-uuid-bad",
            patchedVersion: "10.0.0",
          },
        ]),
        apply: true,
        skipInstall: true,
        registry: {
          async verifyPackageVersion() {
            return { exists: true, deprecated: null };
          },
        },
      });
      expect(result.exitCode).toBe(0);
      expect(result.messages.join("\n")).toMatch(/uuid@11\.1\.1/);
      const pkg = readPackageJson(dir);
      expect(pkg.overrides?.uuid).toBe("11.1.1");
      expect(existsSync(join(dir, "security-metadata.json"))).toBe(false);
    });
  });

  it("does not write when the advisory has no safe override version", async () => {
    await withFixture("npm-still-vulnerable", async (dir) => {
      const result = await runFix({
        cwd: dir,
        audit: createStaticAudit([
          {
            package: "uuid",
            severity: "high",
            range: "*",
            ghsaId: "GHSA-uuid-star",
            patchedVersion: "10.0.0",
          },
        ]),
        apply: true,
        skipInstall: true,
        registry: {
          async verifyPackageVersion() {
            return { exists: true, deprecated: null };
          },
        },
      });
      expect(result.exitCode).toBe(1);
      expect(result.messages.join("\n")).toMatch(
        /Not writing package.json|No patched version|STILL_VULNERABLE/,
      );
    });
  });

  it("rejects NOOP overrides", async () => {
    const result = await runFix({
      cwd: fixtureDir("npm-noop-override"),
      audit: createStaticAudit([qs]),
      apply: true,
      skipInstall: true,
      registry: {
        async verifyPackageVersion() {
          return { exists: true, deprecated: null };
        },
      },
    });
    expect(result.exitCode).toBe(1);
    expect(result.report.validation?.some((i) => i.code === "NOOP_OVERRIDE")).toBe(true);
  });

  it("rejects VERSION_NOT_FOUND", async () => {
    await withFixture("npm-simple", async (dir) => {
      const result = await runFix({
        cwd: dir,
        audit: createStaticAudit([qs]),
        apply: true,
        skipInstall: true,
        registry: {
          async verifyPackageVersion() {
            return { exists: false, deprecated: null };
          },
        },
      });
      expect(result.exitCode).toBe(1);
      expect(result.report.validation?.some((i) => i.code === "VERSION_NOT_FOUND")).toBe(true);
    });
  });

  it("applies an override into package.json only", async () => {
    await withFixture("npm-simple", async (dir) => {
      await writeFile(
        join(dir, ".supplywardenrc.json"),
        JSON.stringify({ upgradeRootThreshold: 0 }),
      );
      const result = await runFix({
        cwd: dir,
        audit: createStaticAudit([qs]),
        apply: true,
        skipInstall: true,
        registry: {
          async verifyPackageVersion() {
            return { exists: true, deprecated: null };
          },
        },
      });
      expect(result.exitCode).toBe(0);
      const pkg = readPackageJson(dir);
      const ov = extractExistingOverrides(pkg);
      expect(ov.some((o) => o.package === "qs" && o.version === "6.11.2")).toBe(true);
      expect(ov.filter((o) => o.package === "qs").every((o) => o.scope.type === "scoped")).toBe(
        true,
      );
      expect(existsSync(join(dir, "security-metadata.json"))).toBe(false);
    });
  });
});

describe("doctor / html", () => {
  it("runs doctor against a fixture", () => {
    const result = runDoctor({ cwd: fixtureDir("npm-simple") });
    expect(result.exitCode).toBe(0);
    expect(result.messages.join("\n")).not.toMatch(/security-metadata/);
  });

  it("renders an action list", async () => {
    const result = await runCheck({
      cwd: fixtureDir("npm-simple"),
      audit: createStaticAudit([qs]),
      registry: {
        async verifyPackageVersion() {
          return { exists: true, deprecated: null };
        },
      },
    });
    const html = renderHtml(result.report);
    expect(html).toMatch(/supplywarden-data/);
    expect(html).toMatch(/"package":"qs"/);
  });
});
