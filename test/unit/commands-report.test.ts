import { describe, expect, it } from "vitest";
import { nextCommands, rewriteLegacyAction } from "../../src/report/commands.js";
import type { CheckEntry, CheckStatus, MetadataEntry } from "../../src/types.js";

function entry(pkg: string, statuses: CheckStatus[], extra: Partial<CheckEntry> = {}): CheckEntry {
  const meta: MetadataEntry = {
    id: pkg,
    status: "active",
    package: pkg,
    forcedVersion: "1.0.0",
    scope: { type: "global" },
    advisories: [],
    reason: "",
    strategy: "override",
    rootPackages: [],
    dependencyChains: [],
    packageManager: "npm",
    manifestPath: "package.json",
    createdAt: "",
    createdBy: "",
    reviewBy: "",
    reviewReason: "",
  };
  return {
    entry: meta,
    status: statuses[0]!,
    statuses,
    suggestedAction: "",
    issues: [],
    ...extra,
  };
}

describe("nextCommands", () => {
  it("maps each status to the current CLI", () => {
    expect(nextCommands(entry("qs", ["NEW"]))).toEqual(["supplywarden fix --apply"]);
    expect(nextCommands(entry("qs", ["REMOVABLE"]))).toEqual(["supplywarden verify qs --apply"]);
    expect(nextCommands(entry("lodash", ["RESOLVED", "REMOVABLE"]))).toEqual([
      "supplywarden verify lodash --apply",
    ]);
    expect(nextCommands(entry("semver", ["PENDING_VERIFY"]))).toEqual(["npm install"]);
    expect(nextCommands(entry("tar", ["VERIFY_FAILED"]))).toEqual(["supplywarden verify tar"]);
    expect(nextCommands(entry("minimist", ["DRIFT"]))).toEqual(["supplywarden sync"]);
    expect(nextCommands(entry("ws", ["UNTRACKED"]))).toEqual(["supplywarden init"]);
    expect(nextCommands(entry("request", ["UNTRACKED", "REMOVABLE"]))).toEqual([
      "supplywarden init",
      "supplywarden verify request --apply",
    ]);
    expect(nextCommands(entry("qs", ["OVERDUE"]))).toEqual(["supplywarden why qs"]);
    expect(nextCommands({ ...entry("picomatch", ["REMOVABLE"]), verifyOutcome: "KEEP" })).toEqual([
      "supplywarden why picomatch",
    ]);
    expect(nextCommands({ ...entry("picomatch", ["OK"]), weakOverride: true })).toEqual([
      "supplywarden fix --apply",
    ]);
    expect(
      nextCommands({ ...entry("picomatch", ["OK"]), auditClear: true, weakOverride: true }),
    ).toEqual(["supplywarden verify picomatch"]);
    expect(nextCommands(entry("picomatch", ["OK"]))).toEqual(["supplywarden verify picomatch"]);
  });
});

describe("rewriteLegacyAction", () => {
  it("replaces retired check --apply and bare verify", () => {
    expect(rewriteLegacyAction("run `supplywarden check --apply`", "lodash")).toContain(
      "supplywarden verify lodash --apply",
    );
    expect(rewriteLegacyAction("run `supplywarden verify --apply`", "request")).toContain(
      "supplywarden verify request --apply",
    );
    expect(rewriteLegacyAction("run `supplywarden verify`", "tar")).toBe("run `supplywarden verify tar`");
    expect(rewriteLegacyAction("run `supplywarden verify tar`", "tar")).toBe("run `supplywarden verify tar`");
    expect(rewriteLegacyAction("run `supplywarden analyze --audit`", "qs")).toContain("supplywarden fix --apply");
  });
});
