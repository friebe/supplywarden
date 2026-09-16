import { describe, expect, it } from "vitest";
import { formatDisplayDate, parseDateLocale, parseTimeZone } from "../../src/util/time.js";

const noonUtc = "2026-09-16T18:12:00.000Z"; // 20:12 in Europe/Berlin (CEST)

describe("date display", () => {
  it("defaults German Berlin", () => {
    expect(formatDisplayDate(noonUtc)).toBe("16.09.2026, 20:12");
  });

  it("formats English in Berlin", () => {
    const text = formatDisplayDate(noonUtc, { dateLocale: "en", timeZone: "Europe/Berlin" });
    expect(text).toMatch(/Sep 16, 2026/);
    expect(text).toMatch(/8:12\sPM/i);
  });

  it("leaves non-dates unchanged", () => {
    expect(formatDisplayDate("now")).toBe("now");
    expect(formatDisplayDate("")).toBe("—");
  });

  it("parses locale aliases", () => {
    expect(parseDateLocale("english")).toBe("en");
    expect(parseDateLocale("de-DE")).toBe("de");
    expect(parseDateLocale("bogus")).toBe("de");
  });

  it("falls back to Berlin on bad timezone", () => {
    expect(parseTimeZone("Not/AZone")).toBe("Europe/Berlin");
    expect(parseTimeZone("UTC")).toBe("UTC");
  });
});
