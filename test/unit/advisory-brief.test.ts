import { describe, expect, it } from "vite-plus/test";
import { advisoryBrief, withDirectPatch } from "../../src/report/model.js";
import { rootUpgradeCommands } from "../../src/fix/upgrade-command.js";

describe("advisory brief", () => {
  it("names the floor and links the CVE", () => {
    expect(
      advisoryBrief([
        {
          severity: "low",
          title: "KaTeX does not escape HTML from insufficient escaping",
          vulnerableRange: "< 0.16.11",
          patchedVersion: "0.16.11",
          cveId: "CVE-2024-28243",
          ghsaId: "GHSA-katex",
        },
      ]),
    ).toBe("https://nvd.nist.gov/vuln/detail/CVE-2024-28243");
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
