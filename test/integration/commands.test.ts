import { readFile, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { createStaticAudit } from "../../src/audit/client.js";
import { createStaticInstall } from "../../src/install/client.js";
import { createLiveRegistry, createOfflineRegistry } from "../../src/registry/verify.js";
import { runInit } from "../../src/commands/init.js";
import { runCheck } from "../../src/commands/check.js";
import { runDoctor } from "../../src/commands/doctor.js";
import { runFix } from "../../src/commands/fix.js";
import { runWhy } from "../../src/commands/why.js";
import { runSync } from "../../src/commands/sync.js";
import { runVerify } from "../../src/commands/verify.js";
import { renderHtml } from "../../src/report/html.js";
import { toMarkdown } from "../../src/report/model.js";
import { extractExistingOverrides, readPackageJson } from "../../src/metadata/sync.js";
import { fixtureDir, withFixture } from "../helpers/fixture-project.js";
import { FIXTURES_ROOT } from "../helpers/fixture-project.js";

describe("runInit", () => {
  it("imports 5 overrides from package.json", async () => {
    await withFixture("npm-five-overrides", async (dir) => {
      const result = await Promise.resolve(runInit({ cwd: dir }));
      expect(result.exitCode).toBe(0);
      expect(result.report.summary.imported).toBe(5);
      const meta = JSON.parse(await readFile(join(dir, "security-metadata.json"), "utf8"));
      expect(meta.entries).toHaveLength(5);
      expect(meta.entries.every((e: { needsReview: boolean }) => e.needsReview)).toBe(true);
      const created = new Date(meta.entries[0].createdAt).getTime();
      const reviewBy = new Date(meta.entries[0].reviewBy).getTime();
      expect(reviewBy - created).toBeGreaterThanOrEqual(6 * 86_400_000);
    });
  });

  it("imports scoped overrides", async () => {
    await withFixture("npm-scoped-override", async (dir) => {
      const result = runInit({ cwd: dir });
      expect(result.report.summary.imported).toBe(1);
      const meta = JSON.parse(await readFile(join(dir, "security-metadata.json"), "utf8"));
      expect(meta.entries[0].scope).toEqual({ type: "scoped", parent: "body-parser" });
      expect(meta.entries[0].package).toBe("qs");
    });
  });
});

describe("runCheck", () => {
  it("lists package.json overrides as UNTRACKED when metadata is missing", async () => {
    const result = await runCheck({ cwd: fixtureDir("npm-five-overrides"), enableAudit: false });
    expect(result.report.entries).toHaveLength(5);
    expect(result.report.entries.every((e) => e.status === "UNTRACKED")).toBe(true);
    expect(result.messages.join("\n")).toMatch(/untracked/);
    const qs = result.report.entries.find((e) => e.entry.package === "qs");
    expect(qs?.suggestedAction).toMatch(/express/);
  });

  it("kitchen-sink fixture reports overdue, removable, drift, pending, verify_failed, untracked", async () => {
    const result = await runCheck({ cwd: fixtureDir("npm-mixed"), enableAudit: false });
    const byPkg = Object.fromEntries(result.report.entries.map((e) => [e.entry.package, e]));
    expect(byPkg.qs?.status).toBe("OVERDUE");
    expect(byPkg.lodash?.statuses).toContain("REMOVABLE");
    expect(byPkg.lodash?.removableReason).toBe("already-at-patched");
    expect(byPkg.request?.statuses).toContain("REMOVABLE");
    expect(byPkg.request?.removableReason).toBe("not-in-tree");
    expect(byPkg.debug?.statuses).toContain("REMOVABLE");
    expect(byPkg.debug?.removableReason).toBe("no-vulnerable-version");
    expect(byPkg.minimist?.status).toBe("DRIFT");
    expect(byPkg.semver?.status).toBe("PENDING_VERIFY");
    expect(byPkg.tar?.status).toBe("VERIFY_FAILED");
    expect(byPkg.ws?.status).toBe("UNTRACKED");
    expect(byPkg.picomatch?.status).toBe("OVERDUE");
    expect(byPkg.picomatch?.dependencyKind).toBe("development");
    expect(byPkg.qs?.dependencyKind).toBe("production");
    expect(byPkg.ip?.status).toBe("OK");
    expect(byPkg["follow-redirects"]?.status).toBe("OK");
    expect(byPkg["follow-redirects"]?.entry.resolution).toMatch(/^verify-keep:/);
    expect(byPkg["nth-check"]?.weakOverride).toBe(true);
    expect(byPkg.fsevents?.dependencyKind).toBe("optional");
    expect(byPkg.qs?.suggestedAction).toMatch(/supplywarden why qs/);
    expect(byPkg.lodash?.suggestedAction).toMatch(/supplywarden verify lodash --apply/);
    expect(byPkg.request?.suggestedAction).toMatch(/supplywarden verify request --apply/);
    expect(byPkg.minimist?.suggestedAction).toMatch(/supplywarden sync/);
    expect(byPkg.semver?.suggestedAction).toMatch(/npm install/);
    expect(byPkg.tar?.suggestedAction).toMatch(/supplywarden verify tar/);
    expect(byPkg.tar?.suggestedAction).not.toMatch(/supplywarden why tar/);
    expect(byPkg.ws?.suggestedAction).toMatch(/supplywarden init/);
    expect(byPkg["nth-check"]?.suggestedAction).toMatch(/fix --apply/);
  });

  it("kitchen-sink audit labels NEW nx-only upgrade, mixed nx+lodash, and override over threshold", async () => {
    const result = await runCheck({
      cwd: fixtureDir("npm-mixed"),
      enableAudit: true,
      audit: createStaticAudit([
        {
          package: "smol-toml",
          severity: "high",
          range: "< 1.4.2",
          ghsaId: "GHSA-7w7h-prm2-qmvq",
          patchedVersion: "1.4.2",
        },
        {
          package: "tslib",
          severity: "high",
          range: "< 2.4.1",
          ghsaId: "GHSA-tslb-mixd-demo",
          patchedVersion: "2.4.1",
        },
        {
          package: "serialize-javascript",
          severity: "high",
          range: "< 6.0.2",
          ghsaId: "GHSA-h9x2-p7j5-2x6r",
          patchedVersion: "6.0.2",
        },
      ]),
      registry: {
        async verifyPackageVersion() {
          return { exists: true, deprecated: null };
        },
        async versionsNewerThan(pkg) {
          if (pkg === "nx") return ["23.2.1", "23.2.5"];
          if (pkg === "lodash") return ["4.17.22"];
          return [];
        },
        async dependencyRange(pkg, version, dep) {
          if (dep === "smol-toml" && pkg === "nx") {
            return version === "23.2.5" ? "^1.4.2" : "^1.3.1";
          }
          if (dep === "tslib") {
            if (pkg === "nx") return version === "23.2.5" ? "^2.4.1" : "2.0.0";
            if (pkg === "lodash") return version === "4.17.22" ? "^2.4.1" : "2.0.0";
          }
          return undefined;
        },
      },
    });
    const byPkg = Object.fromEntries(result.report.entries.map((e) => [e.entry.package, e]));
    expect(byPkg["smol-toml"]?.status).toBe("NEW");
    expect(byPkg["smol-toml"]?.roots).toEqual(["nx"]);
    expect(byPkg["smol-toml"]?.decision?.strategy).toBe("upgrade");
    expect(byPkg["smol-toml"]?.decision?.upgradeTargets).toEqual([
      { name: "nx", from: "23.2.0", to: "23.2.5", skipped: ["23.2.1"] },
    ]);
    expect(byPkg["smol-toml"]?.upgradeCommands).toEqual(["npx nx migrate nx@23.2.5"]);
    expect(byPkg["smol-toml"]?.suggestedAction).toMatch(/nx@23\.2\.0 → 23\.2\.5/);
    expect(byPkg["smol-toml"]?.suggestedAction).toMatch(/not 23\.2\.1/);
    expect(result.messages.join("\n")).toMatch(/NEW smol-toml \(lockfile 1\.3\.1\): nx@23\.2\.0 → 23\.2\.5/);
    expect(toMarkdown(result.report)).toMatch(/## New/);
    expect(toMarkdown(result.report)).toMatch(/nx@23\.2\.0 → 23\.2\.5 \(not 23\.2\.1/);
    expect(byPkg.tslib?.status).toBe("NEW");
    expect(byPkg.tslib?.decision?.strategy).toBe("upgrade");
    expect(byPkg.tslib?.upgradeCommands).toEqual([
      "npm install lodash@4.17.22",
      "npx nx migrate nx@23.2.5",
    ]);
    expect(byPkg["serialize-javascript"]?.status).toBe("NEW");
    expect(byPkg["serialize-javascript"]?.decision?.strategy).toBe("override");
    expect(byPkg["serialize-javascript"]?.roots?.sort()).toEqual(["ava", "jest", "mocha", "webpack"].sort());
  });

  it("loads NEW findings from a Dependabot alert file instead of live audit", async () => {
    const cwd = fixtureDir("npm-mixed");
    const result = await runCheck({
      cwd,
      enableAudit: false,
      alertPath: join(FIXTURES_ROOT, "alerts/mixed.json"),
      registry: createLiveRegistry(cwd),
    });
    const byPkg = Object.fromEntries(result.report.entries.map((e) => [e.entry.package, e]));
    expect(byPkg["smol-toml"]?.status).toBe("NEW");
    expect(byPkg["smol-toml"]?.decision?.upgradeTargets).toEqual([
      { name: "nx", from: "23.2.0", to: "23.2.5", skipped: ["23.2.1"] },
    ]);
    expect(toMarkdown(result.report)).toMatch(/nx@23\.2\.0 → 23\.2\.5 \(not 23\.2\.1/);
    expect(result.messages.join("\n")).toMatch(/alerts: .*untracked finding/);
  });

  it("explains empty fixtures without overrides or metadata", async () => {
    const result = await runCheck({ cwd: fixtureDir("npm-simple"), enableAudit: false });
    expect(result.report.entries).toHaveLength(0);
    expect(result.messages.join("\n")).toMatch(/Nothing to show/);
  });

  it("marks override as REMOVABLE/RESOLVED when vuln is gone", async () => {
    const result = await runCheck({ cwd: fixtureDir("npm-removable"), enableAudit: false });
    expect(result.exitCode).toBe(0);
    expect(result.report.entries[0]!.statuses).toContain("REMOVABLE");
    expect(result.report.entries[0]!.removableReason).toBe("no-vulnerable-version");
    expect(result.report.summary.removable).toBeGreaterThanOrEqual(1);
  });

  it("exits 1 on --strict + overdue high", async () => {
    const result = await runCheck({ cwd: fixtureDir("npm-overdue"), strict: true, enableAudit: false });
    expect(result.exitCode).toBe(1);
    expect(result.report.entries[0]!.statuses).toContain("OVERDUE");
  });

  it("detects DRIFT when package.json is missing the override", async () => {
    const result = await runCheck({ cwd: fixtureDir("npm-drift"), enableAudit: false });
    expect(result.report.entries[0]!.status).toBe("DRIFT");
  });

  it("reports NEW audit findings that are not already overridden", async () => {
    const result = await runCheck({
      cwd: fixtureDir("npm-simple"),
      enableAudit: true,
      audit: createStaticAudit([
        {
          package: "qs",
          severity: "high",
          range: "< 6.11.0",
          ghsaId: "GHSA-qs-high",
          patchedVersion: "6.11.2",
        },
      ]),
    });
    expect(result.report.entries.some((e) => e.status === "NEW" && e.entry.package === "qs")).toBe(
      true,
    );
    expect(result.report.summary.auditNew).toBe(1);
    const qs = result.report.entries.find((e) => e.status === "NEW" && e.entry.package === "qs");
    expect(qs?.suggestedAction).toMatch(/UPGRADE|OVERRIDE/);
    expect(qs?.suggestedAction).toMatch(/express|qs@/);
    expect(qs?.decision?.strategy).toMatch(/upgrade|override/);
  });

  it("suggests a newer root version, not the one already installed", async () => {
    const result = await runCheck({
      cwd: fixtureDir("npm-simple"),
      enableAudit: true,
      audit: createStaticAudit([
        {
          package: "qs",
          severity: "high",
          range: "< 6.11.0",
          ghsaId: "GHSA-qs-high",
          patchedVersion: "6.11.2",
        },
      ]),
      registry: {
        async verifyPackageVersion() {
          return { exists: true, deprecated: null };
        },
        async latestVersion() {
          return "4.21.2";
        },
        async getLatestMatching() {
          return "4.21.2";
        },
        async dependencyRange(pkg, version, dep) {
          if (pkg === "express" && dep === "qs" && version === "4.21.2") return "6.13.0";
          if (pkg === "express" && dep === "qs") return "6.5.0";
          return undefined;
        },
      },
    });
    const qs = result.report.entries.find((e) => e.status === "NEW" && e.entry.package === "qs");
    expect(qs?.decision?.strategy).toBe("upgrade");
    expect(qs?.decision?.upgradeTargets?.[0]).toMatchObject({
      name: "express",
      from: "4.18.2",
      to: "4.21.2",
    });
    expect(qs?.suggestedAction).toMatch(/express@4\.18\.2 → 4\.21\.2/);
    expect(qs?.suggestedAction).toMatch(/npm install express@4\.21\.2/);
    expect(qs?.suggestedAction).not.toMatch(/supplywarden fix --apply/);
    expect(qs?.suggestedAction).not.toMatch(/UPGRADE express@4\.18\.2 —/);
    const html = renderHtml(result.report);
    expect(html).toMatch(/function upgradeHint/);
    expect(html).toContain("express@4.18.2");
    expect(html).toContain("4.21.2");
    expect(toMarkdown(result.report)).toMatch(/express@4\.18\.2 → 4\.21\.2/);
  });

  it("does not flag audit findings covered by an active override", async () => {
    const result = await runCheck({
      cwd: fixtureDir("npm-removable"),
      enableAudit: true,
      audit: createStaticAudit([
        {
          package: "qs",
          severity: "high",
          range: "< 6.11.0",
          ghsaId: "GHSA-qs-high",
          patchedVersion: "6.11.2",
        },
      ]),
    });
    expect(result.report.entries.filter((e) => e.status === "NEW")).toHaveLength(0);
  });

  it("confirms existing override as RESOLVED when live audit is clear", async () => {
    const result = await runCheck({
      cwd: fixtureDir("npm-removable"),
      enableAudit: true,
      audit: createStaticAudit([]),
    });
    expect(result.report.entries[0]!.statuses).toContain("RESOLVED");
    expect(["no-vulnerable-version", "audit-clear"]).toContain(result.report.entries[0]!.removableReason);
  });

  it("strict fails on new audit findings", async () => {
    const result = await runCheck({
      cwd: fixtureDir("npm-simple"),
      strict: true,
      enableAudit: true,
      audit: createStaticAudit([
        { package: "qs", severity: "high", range: "< 6.11.0", patchedVersion: "6.11.2" },
      ]),
    });
    expect(result.exitCode).toBe(1);
  });
});

describe("runWhy / analyze", () => {
  it("finds express as root for qs", () => {
    const result = runWhy({ cwd: fixtureDir("npm-simple"), package: "qs" });
    expect(result.exitCode).toBe(0);
    expect(result.report.summary.roots).toBeGreaterThanOrEqual(1);
    expect(result.messages.join("\n")).toMatch(/express/);
  });

  it("labels picomatch as development-only in npm-mixed", () => {
    const result = runWhy({ cwd: fixtureDir("npm-mixed"), package: "picomatch" });
    expect(result.exitCode).toBe(0);
    expect(result.messages.join("\n")).toMatch(/Tree: development only/);
    expect(result.messages.join("\n")).toMatch(/eslint/);
  });

  it("analyzes qs alert against npm-simple", async () => {
    const result = await runFix({
      cwd: fixtureDir("npm-simple"),
      alertPath: join(FIXTURES_ROOT, "alerts/ghsa-qs-high.json"),
      apply: false,
    });
    expect(result.report.decision?.forcedVersion).toBe("6.11.2");
    expect(result.report.groups?.[0]?.package).toBe("qs");
  });

  it("analyzes without alert file via audit by default", async () => {
    const result = await runFix({
      cwd: fixtureDir("npm-simple"),
      apply: false,
      audit: createStaticAudit([
        {
          package: "qs",
          severity: "high",
          range: "< 6.11.0",
          ghsaId: "GHSA-qs-high",
          patchedVersion: "6.11.2",
        },
      ]),
    });
    expect(result.report.decision?.forcedVersion).toBe("6.11.2");
    expect(result.report.groups?.[0]?.package).toBe("qs");
  });

  it("errors when no alert file and audit is skipped", async () => {
    const result = await runFix({
      cwd: fixtureDir("npm-simple"),
      apply: false,
      enableAudit: false,
    });
    expect(result.exitCode).toBe(1);
    expect(result.messages.join("\n")).toMatch(/skip-audit|alert file/i);
  });

  it("tells you to verify --apply when audit is clear but check has REMOVABLE", async () => {
    const result = await runFix({
      cwd: fixtureDir("npm-mixed"),
      apply: true,
      audit: createStaticAudit([]),
    });
    expect(result.exitCode).toBe(1);
    expect(result.messages.join("\n")).toMatch(/verify --apply/);
    expect(result.messages.join("\n")).toMatch(/lodash|request/);
  });
});

describe("validation gates", () => {
  it("writes a safe override when Dependabot patchedVersion is still inside the range", async () => {
    await withFixture("npm-still-vulnerable", async (dir) => {
      await writeFile(
        join(dir, ".supplywardenrc.json"),
        JSON.stringify({ upgradeRootThreshold: 0 }),
      );
      const result = await runFix({
        cwd: dir,
        alertPath: join(FIXTURES_ROOT, "alerts/uuid-still-vulnerable.json"),
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
      expect(pkg.pnpm?.overrides).toBeUndefined();
    });
  });

  it("does not write when the advisory has no safe override version", async () => {
    await withFixture("npm-still-vulnerable", async (dir) => {
      const result = await runFix({
        cwd: dir,
        alertPath: join(FIXTURES_ROOT, "alerts/uuid-unknown-range.json"),
        apply: true,
        skipInstall: true,
        registry: {
          async verifyPackageVersion() {
            return { exists: true, deprecated: null };
          },
        },
      });
      expect(result.exitCode).toBe(1);
      expect(result.messages.join("\n")).toMatch(/Not writing package.json|No patched version|STILL_VULNERABLE/);
    });
  });

  it("rejects NOOP overrides", async () => {
    const result = await runFix({
      cwd: fixtureDir("npm-noop-override"),
      alertPath: join(FIXTURES_ROOT, "alerts/qs-noop.json"),
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
        alertPath: join(FIXTURES_ROOT, "alerts/ghsa-qs-high.json"),
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

  it("applies override when registry and advisory are valid", async () => {
    await withFixture("npm-simple", async (dir) => {
      await writeFile(
        join(dir, ".supplywardenrc.json"),
        JSON.stringify({ upgradeRootThreshold: 0 }),
      );
      const result = await runFix({
        cwd: dir,
        alertPath: join(FIXTURES_ROOT, "alerts/ghsa-qs-high.json"),
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
      const meta = JSON.parse(await readFile(join(dir, "security-metadata.json"), "utf8"));
      expect(meta.entries[0].status).toBe("active");
      expect(meta.entries[0].reason).toMatch(/root package/);
    });
  });
});

describe("doctor / html / sync", () => {
  it("runs doctor against a fixture", () => {
    const result = runDoctor({ cwd: fixtureDir("npm-simple") });
    expect(result.exitCode).toBe(0);
  });

  it("renders HTML with removable section and chains", async () => {
    const result = await runCheck({ cwd: fixtureDir("npm-removable"), enableAudit: false });
    const html = renderHtml(result.report);
    expect(html).toContain("supplywarden-data");
    expect(html).toContain("qs");
    expect(html).toMatch(/Safe to remove|no-vulnerable-version/);
    expect(html).toMatch(/supplywarden verify qs --apply/);
    expect(JSON.stringify(result.report.entries[0])).toMatch(/roots|express/);
  });

  it("HTML actions use verify <pkg>, not check --apply", async () => {
    const result = await runCheck({ cwd: fixtureDir("npm-mixed"), enableAudit: false });
    const html = renderHtml(result.report);
    const json = html.match(/id="supplywarden-data">([^<]*)/)?.[1];
    expect(json).toBeTruthy();
    const data = JSON.parse(json!);
    const actions = data.entries.map((e: { commands?: string[]; suggestedAction: string }) =>
      [...(e.commands ?? []), e.suggestedAction].join(" "),
    );
    expect(actions.join("\n")).not.toMatch(/check --apply/);
    expect(actions.some((a: string) => a.includes("supplywarden verify lodash --apply"))).toBe(true);
    expect(actions.some((a: string) => a.includes("supplywarden verify request --apply"))).toBe(true);
    expect(actions.some((a: string) => a.includes("npm install"))).toBe(true);
    expect(actions.some((a: string) => a.includes("supplywarden verify tar"))).toBe(true);
    expect(actions.some((a: string) => a.includes("supplywarden why qs"))).toBe(true);
    expect(html).toMatch(/Decide this week/);
    expect(html).toMatch(/title: 'Tracked'/);
    expect(html).toMatch(/data-chip="tracked"/);
    expect(html).toMatch(/<th>Severity<\/th>/);
    expect(html).toMatch(/<th>Scope<\/th>/);
    expect(html).toMatch(/function scopeBadge/);
    const picomatch = data.entries.find((e: { entry: { package: string } }) => e.entry.package === "picomatch");
    expect(picomatch?.dependencyKind).toBe("development");
    const md = toMarkdown(result.report);
    expect(md).toMatch(/\| Package \| Status \| Scope \|/);
    expect(md).toMatch(/picomatch@4\.0\.4 · development \| OVERDUE \| development \|/);
    expect(md).toMatch(/qs@6\.11\.2 \| OVERDUE \| production \|/);
    expect(md).toMatch(/fsevents@2\.3\.3 · optional \| OK \| optional \|/);
    expect(md).toMatch(/follow-redirects@1\.15\.6 \| OK · verified /);
    expect(actions.some((a: string) => a.includes("supplywarden sync"))).toBe(true);
    expect(actions.some((a: string) => a.includes("supplywarden init"))).toBe(true);
    expect(html).toMatch(/function advisoryLinks/);
    expect(html).toMatch(/https:\/\/github.com\/advisories\//);
    expect(JSON.stringify(picomatch)).toMatch(/GHSA-c2c7-rcm5-vvqj/);
  });

  it("sync restores drifted overrides", async () => {
    await withFixture("npm-drift", async (dir) => {
      const result = runSync({ cwd: dir });
      expect(result.exitCode).toBe(0);
      const pkg = readPackageJson(dir);
      expect(pkg.overrides).toMatchObject({ qs: "6.11.2" });
    });
  });

  it("reads legacy .vulnfixrc.json and doctor warns", async () => {
    await withFixture("npm-simple", async (dir) => {
      await writeFile(join(dir, ".vulnfixrc.json"), JSON.stringify({ upgradeRootThreshold: 0 }));
      const doctor = runDoctor({ cwd: dir });
      expect(doctor.messages.join("\n")).toMatch(/legacy config/);
      const result = await runFix({
        cwd: dir,
        alertPath: join(FIXTURES_ROOT, "alerts/ghsa-qs-high.json"),
        apply: false,
      });
      expect(result.report.decision?.strategy).toBe("override");
    });
  });
});

describe("runVerify", () => {
  it("confirms removable when audit is clear", async () => {
    await withFixture("npm-removable", async (dir) => {
      const result = await runVerify({
        cwd: dir,
        skipInstall: true,
        audit: createStaticAudit([]),
        install: createStaticInstall(),
      });
      expect(result.report.entries[0]!.verifyOutcome).toBe("CONFIRMED_REMOVABLE");
      const pkg = readPackageJson(dir);
      expect(pkg.overrides).toMatchObject({ qs: "6.11.2" });
    });
  });

  it("keeps override when audit still reports the package", async () => {
    await withFixture("npm-removable", async (dir) => {
      const result = await runVerify({
        cwd: dir,
        skipInstall: true,
        audit: createStaticAudit([
          { package: "qs", severity: "high", range: "< 6.11.0", ghsaId: "GHSA-qs-high" },
        ]),
        install: createStaticInstall(),
        registry: createOfflineRegistry(),
      });
      expect(result.report.entries[0]!.verifyOutcome).toBe("KEEP");
      const meta = JSON.parse(await readFile(join(dir, "security-metadata.json"), "utf8"));
      expect(meta.entries[0].status).toBe("active");
      expect(meta.entries[0].resolution).toMatch(/^verify-keep:/);
      expect(meta.entries[0].resolvedAt).toBeTruthy();
      expect(meta.entries[0].resolvedBy).toBeTruthy();
      const resolved = new Date(meta.entries[0].resolvedAt).getTime();
      const reviewBy = new Date(meta.entries[0].reviewBy).getTime();
      expect(reviewBy - resolved).toBeGreaterThanOrEqual(6 * 86_400_000);
    });
  });

  it("apply drops confirmed overrides", async () => {
    await withFixture("npm-removable", async (dir) => {
      const result = await runVerify({
        cwd: dir,
        apply: true,
        skipInstall: true,
        audit: createStaticAudit([]),
        install: createStaticInstall(),
      });
      expect(result.exitCode).toBe(0);
      const meta = JSON.parse(await readFile(join(dir, "security-metadata.json"), "utf8"));
      expect(meta.entries[0].status).toBe("resolved");
      expect(meta.entries[0].resolvedAt).toBeTruthy();
      expect(meta.entries[0].resolvedBy).toBeTruthy();
      expect(meta.entries[0].resolution).toMatch(/^verify-confirmed:/);
      const pkg = readPackageJson(dir);
      expect(pkg.overrides).toBeUndefined();
    });
  });

  it("drops leftover REMOVABLE from check without requiring npm install", async () => {
    await withFixture("npm-mixed", async (dir) => {
      const result = await runVerify({
        cwd: dir,
        apply: true,
        audit: createStaticAudit([]),
        install: createStaticInstall(
          false,
          "npm error code EOVERRIDE\nnpm error Override for semver@7.5.1 conflicts with direct dependency",
        ),
      });
      expect(result.exitCode).toBe(0);
      expect(result.messages.join("\n")).toMatch(/CONFIRMED_REMOVABLE/);
      const pkg = readPackageJson(dir);
      expect(pkg.overrides?.lodash).toBeUndefined();
      expect(pkg.overrides?.request).toBeUndefined();
      expect(pkg.overrides?.qs).toBe("6.11.2");
    });
  });

  it("keeps override when install fails", async () => {
    await withFixture("npm-removable", async (dir) => {
      const result = await runVerify({
        cwd: dir,
        audit: createStaticAudit([]),
        install: createStaticInstall(false, "peer conflict"),
      });
      expect(result.exitCode).toBe(1);
      expect(result.report.entries[0]!.verifyOutcome).toBe("VERIFY_FAILED");
      const pkg = readPackageJson(dir);
      expect(pkg.overrides).toMatchObject({ qs: "6.11.2" });
      const meta = JSON.parse(await readFile(join(dir, "security-metadata.json"), "utf8"));
      expect(meta.entries[0].status).toBe("verify_failed");
      expect(meta.entries[0].resolvedAt).toBeTruthy();
      expect(meta.entries[0].resolution).toMatch(/verify-failed/);
      expect(meta.entries[0].resolution).toMatch(/peer conflict/);
    });
  });

  it("probes only the named package", async () => {
    await withFixture("npm-mixed", async (dir) => {
      const result = await runVerify({
        cwd: dir,
        package: "lodash",
        apply: true,
        skipInstall: true,
        audit: createStaticAudit([]),
        install: createStaticInstall(),
      });
      expect(result.exitCode).toBe(0);
      expect(result.report.entries).toHaveLength(1);
      expect(result.report.entries[0]!.entry.package).toBe("lodash");
      expect(result.report.entries[0]!.verifyOutcome).toBe("CONFIRMED_REMOVABLE");
      const pkg = readPackageJson(dir);
      expect(pkg.overrides?.lodash).toBeUndefined();
      expect(pkg.overrides?.request).toBe("2.88.2");
    });
  });

  it("probes a named override even when check has not marked it REMOVABLE", async () => {
    await withFixture("npm-mixed", async (dir) => {
      const result = await runVerify({
        cwd: dir,
        package: "qs",
        skipInstall: true,
        audit: createStaticAudit([]),
        install: createStaticInstall(),
      });
      expect(result.report.entries).toHaveLength(1);
      expect(result.report.entries[0]!.entry.package).toBe("qs");
      expect(result.report.entries[0]!.verifyOutcome).toBe("CONFIRMED_REMOVABLE");
      const pkg = readPackageJson(dir);
      expect(pkg.overrides?.qs).toBe("6.11.2");
    });
  });

  it("records KEEP so the next check shows verified date instead of overdue", async () => {
    await withFixture("npm-mixed", async (dir) => {
      const before = await runCheck({ cwd: dir, enableAudit: false });
      expect(before.report.entries.find((e) => e.entry.package === "picomatch")?.status).toBe(
        "OVERDUE",
      );
      const result = await runVerify({
        cwd: dir,
        package: "picomatch",
        skipInstall: true,
        audit: createStaticAudit([
          { package: "picomatch", severity: "high", range: "< 4.0.3", ghsaId: "GHSA-c2c7-rcm5-vvqj" },
        ]),
        install: createStaticInstall(),
        registry: createOfflineRegistry(),
      });
      expect(result.report.entries[0]!.verifyOutcome).toBe("KEEP");
      const after = await runCheck({ cwd: dir, enableAudit: false });
      const picomatch = after.report.entries.find((e) => e.entry.package === "picomatch");
      expect(picomatch?.status).toBe("OK");
      expect(picomatch?.statuses).not.toContain("OVERDUE");
      expect(picomatch?.entry.resolution).toMatch(/^verify-keep:/);
      const html = renderHtml(after.report);
      expect(html).toMatch(/verified /);
      expect(toMarkdown(after.report)).toMatch(/verified /);
    });
  });

  it("keeps override when audit fails and lockfile still matches stored advisories", async () => {
    await withFixture("npm-mixed", async (dir) => {
      const result = await runVerify({
        cwd: dir,
        package: "qs",
        skipInstall: true,
        audit: createStaticAudit([], "npm audit failed"),
        install: createStaticInstall(),
        registry: createOfflineRegistry(),
      });
      expect(result.report.entries[0]!.verifyOutcome).toBe("KEEP");
    });
  });

  it("exits 1 when the named package has no override", async () => {
    await withFixture("npm-mixed", async (dir) => {
      const result = await runVerify({
        cwd: dir,
        package: "left-pad",
        skipInstall: true,
        audit: createStaticAudit([]),
        install: createStaticInstall(),
      });
      expect(result.exitCode).toBe(1);
      expect(result.messages.join("\n")).toMatch(/no override for left-pad/);
    });
  });

  const expressQsRegistry = createOfflineRegistry(
    {
      express: ["4.18.2", "4.18.3", "4.21.2"],
      qs: ["6.5.0", "6.11.2"],
    },
    {
      express: {
        "4.18.3": { qs: "6.5.0" },
        "4.21.2": { qs: "^6.11.2" },
      },
    },
  );

  it("KEEP with few roots suggests a proven root upgrade like check", async () => {
    await withFixture("npm-overdue", async (dir) => {
      const result = await runVerify({
        cwd: dir,
        package: "qs",
        skipInstall: true,
        audit: createStaticAudit([
          { package: "qs", severity: "high", range: "< 6.11.0", ghsaId: "GHSA-qs-high" },
        ]),
        install: createStaticInstall(),
        registry: expressQsRegistry,
      });
      const entry = result.report.entries[0]!;
      expect(entry.verifyOutcome).toBe("KEEP");
      expect(entry.decision?.strategy).toBe("upgrade");
      expect(entry.decision?.upgradeTargets).toEqual([
        { name: "express", from: "4.18.2", to: "4.21.2", skipped: ["4.18.3"] },
      ]);
      expect(entry.upgradeCommands).toEqual(["npm install express@4.21.2"]);
      expect(entry.suggestedAction).toMatch(/npm install express@4\.21\.2/);
      expect(result.messages.join("\n")).toMatch(/UPGRADE express@4\.18\.2 → 4\.21\.2/);
    });
  });

  it("KEEP stays override when roots exceed upgradeRootThreshold", async () => {
    await withFixture("npm-overdue", async (dir) => {
      await writeFile(join(dir, ".supplywardenrc.json"), JSON.stringify({ upgradeRootThreshold: 0 }));
      const result = await runVerify({
        cwd: dir,
        package: "qs",
        skipInstall: true,
        audit: createStaticAudit([
          { package: "qs", severity: "high", range: "< 6.11.0", ghsaId: "GHSA-qs-high" },
        ]),
        install: createStaticInstall(),
        registry: expressQsRegistry,
      });
      expect(result.report.entries[0]!.decision?.strategy).toBe("override");
      expect(result.report.entries[0]!.upgradeCommands).toBeUndefined();
      expect(result.messages.join("\n")).not.toMatch(/UPGRADE/);
    });
  });

  it("verify --apply runs the KEEP upgrade when autoApplyRootUpgrade is on", async () => {
    await withFixture("npm-overdue", async (dir) => {
      await writeFile(
        join(dir, ".supplywardenrc.json"),
        JSON.stringify({ autoApplyRootUpgrade: true }),
      );
      const calls: string[] = [];
      const result = await runVerify({
        cwd: dir,
        package: "qs",
        apply: true,
        audit: createStaticAudit([
          { package: "qs", severity: "high", range: "< 6.11.0", ghsaId: "GHSA-qs-high" },
        ]),
        install: {
          async install() {
            return { ok: true };
          },
          async runCommand(_cwd, file, args) {
            calls.push(`${file} ${args.join(" ")}`);
            return { ok: true };
          },
        },
        registry: expressQsRegistry,
      });
      expect(result.report.entries[0]!.verifyOutcome).toBe("KEEP");
      expect(calls).toEqual(["npm install express@4.21.2"]);
      expect(result.messages.join("\n")).toMatch(/Ran `npm install express@4\.21\.2`/);
      const pkg = readPackageJson(dir);
      expect(pkg.overrides).toMatchObject({ qs: "6.11.2" });
    });
  });
});
