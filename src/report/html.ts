import { existsSync, readFileSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import type { ReportModel } from "../types.js";
import { withReportCommands } from "./commands.js";
import { loadConfig } from "../config.js";
import { formatDisplayDate } from "../util/time.js";
import { formatVerifiedKeep } from "./verified.js";

function loadTemplate(): string {
  const here = dirname(fileURLToPath(import.meta.url));
  const candidates = [
    join(here, "../../templates/report.html"),
    join(here, "../templates/report.html"),
    join(here, "templates/report.html"),
  ];
  for (const path of candidates) {
    if (existsSync(path)) return readFileSync(path, "utf8");
  }
  return FALLBACK_HTML;
}

export function renderHtml(report: ReportModel): string {
  const template = loadTemplate();
  const config = loadConfig(report.cwd || ".");
  const dateOpts = {
    dateLocale: report.dateLocale ?? config.dateLocale,
    timeZone: report.timeZone ?? config.timeZone,
  };
  const normalized: ReportModel = {
    ...report,
    dateLocale: dateOpts.dateLocale,
    timeZone: dateOpts.timeZone,
    generatedAt: formatDisplayDate(report.generatedAt, dateOpts),
    entries: report.entries.map((e) => {
      const next = withReportCommands(e);
      return {
        ...next,
        verifiedNote: formatVerifiedKeep(next.entry, dateOpts),
        entry: {
          ...next.entry,
          reviewBy: formatDisplayDate(next.entry.reviewBy, dateOpts),
          resolvedAt: next.entry.resolvedAt
            ? formatDisplayDate(next.entry.resolvedAt, dateOpts)
            : next.entry.resolvedAt,
        },
      };
    }),
  };
  const json = JSON.stringify(normalized).replace(/</g, "\\u003c");
  return template.replace("<!--SUPPLYWARDEN_DATA-->", json);
}

export function writeHtml(report: ReportModel, path: string): string {
  writeFileSync(path, renderHtml(report));
  return path;
}

/** Used only if templates/report.html is missing from the install. */
const FALLBACK_HTML = `<!DOCTYPE html>
<html lang="en">
<head><meta charset="utf-8"/><title>supplywarden</title></head>
<body>
<script type="application/json" id="supplywarden-data"><!--SUPPLYWARDEN_DATA--></script>
<p>Missing templates/report.html next to the CLI install.</p>
</body>
</html>
`;
