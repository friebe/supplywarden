import { describe, expect, it } from "vite-plus/test";
import { advisoryBrief, withDirectPatch } from "../../src/report/model.js";
import { rootUpgradeCommands } from "../../src/fix/upgrade-command.js";

describe("advisory brief", () => {
  it("names the title, the range, and the patched version", () => {
    expect(
      advisoryBrief([
        {
          severity: "low",
          title: "KaTeX does not escape HTML",
          vulnerableRange: "< 0.16.11",
          patchedVersion: "0.16.11",
        },
      ]),
    ).toBe("KaTeX does not escape HTML: < 0.16.11, patched in 0.16.11");
  });

  it("installs a direct package at the advisory patch", () => {
    const targets = withDirectPatch("katex", "0.16.11", [{ name: "katex", from: "0.16.10" }]);
    expect(rootUpgradeCommands("npm", targets).map((command) => command.display)).toEqual([
      "npm install katex@0.16.11",
    ]);
  });

  it("does not invent a version for a parent root", () => {
    const targets = withDirectPatch("katex", "0.16.11", [{ name: "marked", from: "4.0.0" }]);
    expect(targets[0]?.to).toBeUndefined();
  });
});
