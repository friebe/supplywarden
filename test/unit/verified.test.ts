import { describe, expect, it } from "vitest";
import { formatVerifiedKeep } from "../../src/report/verified.js";

describe("formatVerifiedKeep", () => {
  it("formats date and actor from a KEEP record", () => {
    expect(
      formatVerifiedKeep(
        {
          resolution: "verify-keep: audit still reports 1 finding(s)",
          resolvedAt: "2026-09-17T09:35:00.000Z",
          resolvedBy: "jan",
        },
        { dateLocale: "de", timeZone: "Europe/Berlin" },
      ),
    ).toMatch(/^verified .+ jan$/);
  });

  it("ignores other resolutions", () => {
    expect(
      formatVerifiedKeep({
        resolution: "verify-failed: peer conflict",
        resolvedAt: "2026-09-17T09:35:00.000Z",
        resolvedBy: "jan",
      }),
    ).toBeUndefined();
  });
});
