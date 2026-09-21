import { userInfo } from "node:os";
import { afterEach, describe, expect, it } from "vitest";
import { actorName } from "../../src/config.js";

const KEYS = ["SUPPLYWARDEN_USER", "VULNFIX_USER", "USER", "USERNAME", "LOGNAME"] as const;

describe("actorName", () => {
  const previous = Object.fromEntries(KEYS.map((key) => [key, process.env[key]]));

  afterEach(() => {
    for (const key of KEYS) {
      if (previous[key] === undefined) delete process.env[key];
      else process.env[key] = previous[key];
    }
  });

  it("prefers SUPPLYWARDEN_USER", () => {
    process.env.SUPPLYWARDEN_USER = "jan";
    process.env.USER = "other";
    expect(actorName()).toBe("jan");
  });

  it("uses the OS login when env is empty", () => {
    for (const key of KEYS) delete process.env[key];
    expect(actorName()).toBe(userInfo().username);
    expect(actorName()).not.toBe("unknown");
  });
});
