import { readFile, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { createStaticAudit } from "../../src/audit/client.js";
import { runInit } from "../../src/commands/init.js";
import { runCheck } from "../../src/commands/check.js";
import { runDoctor } from "../../src/commands/doctor.js";
import { runFix } from "../../src/commands/fix.js";
import { runWhy } from "../../src/commands/why.js";
import { runSync } from "../../src/commands/sync.js";
import { runVerify } from "../../src/commands/verify.js";
import { createStaticInstall } from "../../src/install/client.js";
import { renderHtml } from "../../src/report/html.js";
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
    const result = await runCheck({ cwd: fixtureDir("npm-five-overrides") });
    expect(result.report.entries).toHaveLength(5);
    expect(result.report.entries.every((e) => e.status === "UNTRACKED")).toBe(true);
    expect(result.messages.join("\n")).toMatch(/untracked/);
  });

  it("kitchen-sink fixture reports overdue, removable, drift, pending, verify_failed, untracked", async () => {
    const result = await runCheck({ cwd: fixtureDir("npm-mixed") });
    const byPkg = Object.fromEntries(result.report.entries.map((e) => [e.entry.package, e]));
    expect(byPkg.qs?.status).toBe("OVERDUE");
    expect(byPkg.lodash?.statuses).toContain("REMOVABLE");
    expect(byPkg.minimist?.status).toBe("DRIFT");
    expect(byPkg.semver?.status).toBe("PENDING_VERIFY");
    expect(byPkg.tar?.status).toBe("VERIFY_FAILED");
    expect(byPkg.ws?.status).toBe("UNTRACKED");
    expect(byPkg.qs?.suggestedAction).toMatch(/supplywarden why qs/);
    expect(byPkg.lodash?.suggestedAction).toMatch(/supplywarden (?:verify --apply|check --apply)/);
    expect(byPkg.minimist?.suggestedAction).toMatch(/supplywarden sync/);
    expect(byPkg.semver?.suggestedAction).toMatch(/supplywarden verify/);
    expect(byPkg.tar?.suggestedAction).toMatch(/supplywarden why tar/);
    expect(byPkg.tar?.suggestedAction).toMatch(/supplywarden verify/);
    expect(byPkg.ws?.suggestedAction).toMatch(/supplywarden init/);
  });

  it("explains empty fixtures without overrides or metadata", async () => {
    const result = await runCheck({ cwd: fixtureDir("npm-simple") });
    expect(result.report.entries).toHaveLength(0);
    expect(result.messages.join("\n")).toMatch(/Nothing to show/);
  });

  it("marks override as REMOVABLE/RESOLVED when vuln is gone", async () => {
    const result = await runCheck({ cwd: fixtureDir("npm-removable") });
    expect(result.exitCode).toBe(0);
    expect(result.report.entries[0]!.statuses).toContain("REMOVABLE");
    expect(result.report.entries[0]!.removableReason).toBe("no-vulnerable-version");
    expect(result.report.summary.removable).toBeGreaterThanOrEqual(1);
  });

  it("exits 1 on --strict + overdue high", async () => {
    const result = await runCheck({ cwd: fixtureDir("npm-overdue"), strict: true });
    expect(result.exitCode).toBe(1);
    expect(result.report.entries[0]!.statuses).toContain("OVERDUE");
  });

  it("detects DRIFT when package.json is missing the override", async () => {
    const result = await runCheck({ cwd: fixtureDir("npm-drift") });
    expect(result.report.entries[0]!.status).toBe("DRIFT");
  });

  it("apply resolves removable entries", async () => {
    await withFixture("npm-removable", async (dir) => {
      const result = await runCheck({ cwd: dir, apply: true, yes: true });
      expect(result.exitCode).toBe(0);
      const meta = JSON.parse(await readFile(join(dir, "security-metadata.json"), "utf8"));
      expect(meta.entries[0].status).toBe("resolved");
      const pkg = readPackageJson(dir);
      expect(pkg.overrides).toBeUndefined();
    });
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

  it("analyzes qs alert against npm-simple", async () => {
    const result = await runFix({
      cwd: fixtureDir("npm-simple"),
      alertPath: join(FIXTURES_ROOT, "alerts/ghsa-qs-high.json"),
      apply: false,
    });
    expect(result.report.decision?.forcedVersion).toBe("6.11.2");
    expect(result.report.groups?.[0]?.package).toBe("qs");
  });

  it("analyzes without alert file when audit provides findings", async () => {
    const result = await runFix({
      cwd: fixtureDir("npm-simple"),
      apply: false,
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
    expect(result.report.decision?.forcedVersion).toBe("6.11.2");
    expect(result.report.groups?.[0]?.package).toBe("qs");
  });

  it("errors when no alert file and audit is disabled", async () => {
    const result = await runFix({
      cwd: fixtureDir("npm-simple"),
      apply: false,
      enableAudit: false,
    });
    expect(result.exitCode).toBe(1);
    expect(result.messages.join("\n")).toMatch(/alert\.json/i);
  });
});

describe("validation gates", () => {
  it("rejects STILL_VULNERABLE overrides", async () => {
    await withFixture("npm-still-vulnerable", async (dir) => {
      const result = await runFix({
        cwd: dir,
        alertPath: join(FIXTURES_ROOT, "alerts/uuid-still-vulnerable.json"),
        apply: true,
        yes: true,
        skipInstall: true,
        registry: {
          async verifyPackageVersion() {
            return { exists: true, deprecated: null };
          },
        },
      });
      expect(result.exitCode).toBe(1);
      expect(result.report.validation?.some((i) => i.code === "STILL_VULNERABLE")).toBe(true);
    });
  });

  it("rejects NOOP overrides", async () => {
    const result = await runFix({
      cwd: fixtureDir("npm-noop-override"),
      alertPath: join(FIXTURES_ROOT, "alerts/qs-noop.json"),
      apply: true,
      yes: true,
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
        yes: true,
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
        yes: true,
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
    const result = await runCheck({ cwd: fixtureDir("npm-removable") });
    const html = renderHtml(result.report);
    expect(html).toContain("supplywarden-data");
    expect(html).toContain("qs");
    expect(html).toMatch(/Safe to remove|no-vulnerable-version/);
    expect(html).toMatch(/supplywarden check --apply|supplywarden verify --apply/);
    expect(JSON.stringify(result.report.entries[0])).toMatch(/roots|express/);
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
      });
      expect(result.report.entries[0]!.verifyOutcome).toBe("KEEP");
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
      const pkg = readPackageJson(dir);
      expect(pkg.overrides).toBeUndefined();
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
    });
  });
});
