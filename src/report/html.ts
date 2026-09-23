import { existsSync, readFileSync, writeFileSync } from "node:fs";
import { dirname, isAbsolute, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import type { ReportModel } from "../types.js";
import { withReportCommands } from "./commands.js";
import { loadConfig } from "../config.js";
import { formatDisplayDate } from "../util/time.js";
import { formatVerifiedKeep } from "./verified.js";

const DATA_MARKER = "<!--SUPPLYWARDEN_DATA-->";

function builtInTemplate(name: "default" | "compact"): string | undefined {
  const here = dirname(fileURLToPath(import.meta.url));
  const filename = name === "compact" ? "report-compact.html" : "report.html";
  const candidates = [
    join(here, "../../templates", filename),
    join(here, "../templates", filename),
    join(here, "templates", filename),
  ];
  for (const path of candidates) {
    if (existsSync(path)) return readFileSync(path, "utf8");
  }
  return undefined;
}

function loadTemplate(cwd: string, configured: string): string {
  const builtIn =
    configured === "default" || configured === "compact"
      ? builtInTemplate(configured)
      : undefined;
  const customPath =
    configured !== "default" && configured !== "compact"
      ? isAbsolute(configured)
        ? configured
        : resolve(cwd, configured)
      : undefined;
  const template = builtIn ?? (customPath && existsSync(customPath)
    ? readFileSync(customPath, "utf8")
    : undefined);

  if (!template) {
    if (configured === "default") return FALLBACK_HTML;
    throw new Error(
      customPath
        ? `HTML template not found: ${customPath}`
        : `Built-in HTML template not found: ${configured}`,
    );
  }
  if (!template.includes(DATA_MARKER)) {
    throw new Error(`HTML template must contain ${DATA_MARKER}`);
  }
  return template;
}

export function renderHtml(report: ReportModel): string {
  const cwd = report.cwd || ".";
  const config = loadConfig(cwd);
  const template = loadTemplate(cwd, config.htmlTemplate);
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
  return template.replace(DATA_MARKER, json);
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
