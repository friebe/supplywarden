import type { Finding, ReportModel } from "../types.js";
import { formatDisplayDate, nowIso } from "../util/time.js";

export function emptyReport(cwd: string, title: string): ReportModel {
  return {
    title,
    generatedAt: nowIso(),
    cwd,
    summary: {},
    entries: [],
  };
}

export function toMarkdown(report: ReportModel): string {
  const lines: string[] = [`# ${report.title}`, ""];
  lines.push(`Generated: ${formatDisplayDate(report.generatedAt)}`, "");
  const summary = Object.entries(report.summary)
    .map(([k, v]) => `**${k}:** ${v}`)
    .join(" · ");
  if (summary) lines.push(summary, "");

  if (report.decision) {
    lines.push(`**Recommendation:** ${report.decision.strategy.toUpperCase()}`, "");
    lines.push(report.decision.reason, "");
  }

  if (report.groups?.length) {
    for (const group of report.groups) {
      lines.push(`## ${group.package}`, "");
      for (const a of group.advisories) {
        lines.push(
          `- ${a.ghsaId ?? "—"} ${a.severity} ${a.vulnerableRange} patched ${a.patchedVersion ?? "—"}`,
        );
      }
      lines.push("");
    }
  }

  if (report.validation?.length) {
    lines.push("## Validation", "");
    for (const issue of report.validation) {
      lines.push(`- **${issue.code}**${issue.blocking ? " (blocking)" : ""}: ${issue.message}`);
    }
    lines.push("");
  }

  if (report.entries.length) {
    lines.push("## What to do", "");
    for (const e of report.entries) lines.push(formatFinding(e), "");
  }

  return lines.join("\n");
}

export function findingLines(e: Finding): string[] {
  const severity = e.severity !== "unknown" ? `, ${e.severity}` : "";
  const via = e.roots.length ? `, via ${e.roots.join(", ")}` : "";
  const lines = [`${e.package}${severity}${via}`];
  for (const command of e.commands) lines.push(command);
  if (e.summary) lines.push(e.summary);
  return lines;
}

function formatFinding(e: Finding): string {
  const [headline, ...rest] = findingLines(e);
  const commands = new Set(e.commands);
  return [
    `- **${headline}**`,
    ...rest.map((line) => (commands.has(line) ? `  - \`${line}\`` : `  - ${line}`)),
  ].join("\n");
}
