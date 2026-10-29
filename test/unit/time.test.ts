import { describe, expect, it } from "vite-plus/test";
import { formatDisplayDate } from "../../src/util/time.js";

const noonUtc = "2026-09-16T18:12:00.000Z";

describe("date display", () => {
  it("formats an instant in the machine zone", () => {
    const text = formatDisplayDate(noonUtc);
    expect(text).toMatch(/2026/);
    expect(text).not.toBe(noonUtc);
  });

  it("leaves non-dates unchanged", () => {
    expect(formatDisplayDate("now")).toBe("now");
    expect(formatDisplayDate("")).toBe("—");
  });
});
