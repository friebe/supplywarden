import type { Advisory, Finding, ReportModel } from "../types.js";
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

/** Title, vulnerable range, and the version the advisory calls patched. */
export function advisoryBrief(advisories: Advisory[]): string {
  return advisories
    .map((advisory) => {
      const name = advisory.title?.trim() || advisory.ghsaId || advisory.cveId;
      const range =
        advisory.vulnerableRange && advisory.vulnerableRange !== "*"
          ? advisory.vulnerableRange
          : undefined;
      const patched = advisory.patchedVersion ? `patched in ${advisory.patchedVersion}` : undefined;
      const detail = [range, patched].filter(Boolean).join(", ");
      if (name && detail) return `${name}: ${detail}`;
      return name || detail || "";
    })
    .filter(Boolean)
    .join(" ");
}

/** A direct dependency can move to the advisory's patched version without a registry proof. */
export function withDirectPatch(
  pkg: string,
  forced: string | undefined,
  targets: Array<{ name: string; from?: string; to?: string; skipped?: string[] }>,
) {
  if (!forced) return targets;
  return targets.map((target) =>
    !target.to && target.name === pkg ? { ...target, to: forced } : target,
  );
}

export function findingLines(e: Finding): string[] {
  const severity = e.severity !== "unknown" ? `, ${e.severity}` : "";
  const via = e.roots.length ? `, via ${e.roots.join(", ")}` : "";
  const lines = [`${e.package}${severity}${via}`];
  if (e.advisory) lines.push(e.advisory);
  for (const trail of e.trails ?? []) {
    if (!trail.path.includes("→") && !trail.range) continue;
    const range = trail.range ? ` asks for ${e.package}@${trail.range}` : "";
    lines.push(`${trail.path}${range}`);
  }
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
