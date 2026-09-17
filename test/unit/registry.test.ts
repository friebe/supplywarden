import { describe, expect, it } from "vitest";
import { join } from "node:path";
import {
  createLiveRegistry,
  createOfflineRegistry,
  dependencyRangeFromPackument,
  versionsNewerThanFromPackument,
  type NpmPackument,
} from "../../src/registry/verify.js";
import { FIXTURES_ROOT } from "../helpers/fixture-project.js";

const packument: NpmPackument = {
  "dist-tags": { latest: "23.3.0" },
  versions: {
    "23.2.0": { dependencies: { "smol-toml": "^1.3.1" } },
    "23.2.1": { dependencies: { "smol-toml": "^1.3.1" } },
    "23.2.2-beta.0": { dependencies: { "smol-toml": "^1.4.2" } },
    "23.3.0": { dependencies: { "smol-toml": "^1.4.2" } },
  },
};

describe("packument helpers", () => {
  it("lists newer stable versions ascending and skips prereleases", () => {
    expect(versionsNewerThanFromPackument(packument, "23.2.0")).toEqual(["23.2.1", "23.3.0"]);
  });

  it("reads the declared dependency range", () => {
    expect(dependencyRangeFromPackument(packument, "23.2.1", "smol-toml")).toBe("^1.3.1");
    expect(dependencyRangeFromPackument(packument, "23.3.0", "smol-toml")).toBe("^1.4.2");
  });
});

describe("offline registry", () => {
  it("returns undefined versionsNewerThan when the package is unknown", async () => {
    const registry = createOfflineRegistry({ nx: ["23.2.0"] });
    expect(await registry.versionsNewerThan("express", "4.18.2")).toBeUndefined();
    expect(await registry.versionsNewerThan("nx", "23.2.0")).toEqual([]);
  });
});

describe("registry overlay", () => {
  it("stubs nx so 23.2.1 is skipped in the kitchen-sink fixture", async () => {
    const registry = createLiveRegistry(join(FIXTURES_ROOT, "npm-mixed"));
    expect(await registry.versionsNewerThan("nx", "23.2.0")).toEqual(["23.2.1", "23.2.5"]);
    expect(await registry.dependencyRange("nx", "23.2.1", "smol-toml")).toBe("^1.3.1");
    expect(await registry.dependencyRange("nx", "23.2.5", "smol-toml")).toBe("^1.4.2");
  });
});
