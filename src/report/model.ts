import type { CheckEntry, ReportModel } from "../types.js";
import { removableReasonLabel } from "../check/classify.js";
import { nowIso } from "../util/time.js";

export function emptyReport(cwd: string, title: string): ReportModel {
  return {
    title,
    generatedAt: nowIso(),
    cwd,
    summary: {},
    entries: [],
  };
}

function ghsaList(entry: CheckEntry): string {
  return entry.entry.advisories.map((a) => a.ghsaId).filter(Boolean).join(", ") || "—";
}

function canRemove(e: CheckEntry): boolean {
  return e.statuses.includes("REMOVABLE") || e.statuses.includes("RESOLVED");
}

export function toMarkdown(report: ReportModel): string {
  const lines: string[] = [`# ${report.title}`, ""];
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
      lines.push(`## ${group.package} – ${group.advisories.length} Advisories (max: ${group.maxSeverity.toUpperCase()})`, "");
      lines.push("| GHSA | Severity | Vulnerable | Patched |", "|------|----------|------------|---------|");
      for (const a of group.advisories) {
        lines.push(
          `| ${a.ghsaId ?? "—"} | ${a.severity} | ${a.vulnerableRange} | ${a.patchedVersion ?? "—"} |`,
        );
      }
      lines.push("", `**forcedVersion:** ${group.forcedVersion ?? "—"}`, "");
    }
  }

  if (report.validation?.length) {
    lines.push("## Validation", "");
    for (const issue of report.validation) {
      lines.push(`- **${issue.code}**${issue.blocking ? " (blocking)" : ""}: ${issue.message}`);
    }
    lines.push("");
  }

  if (report.impact) {
    lines.push(
      `**Lockfile impact:** ${report.impact.changedPackages} package(s) would change (warn: ${report.impact.warning ? "yes" : "no"}, block: ${report.impact.blocked ? "yes" : "no"})`,
      "",
    );
  }

  const removable = report.entries.filter(canRemove);
  if (removable.length) {
    lines.push("## Safe to remove", "");
    lines.push(
      "| Package | Status | Reason | GHSA | Forced |",
      "|---------|--------|------------|------|--------|",
    );
    for (const e of removable) {
      lines.push(
        `| ${e.entry.package}@${e.entry.forcedVersion} | ${e.statuses.join(" + ")} | ${removableReasonLabel(e.removableReason)} | ${ghsaList(e)} | ${e.entry.forcedVersion} |`,
      );
    }
    lines.push("");
  }

  if (report.entries.length) {
    lines.push("| Package | Status | Recommendation |", "|---------|--------|----------------|");
    for (const e of report.entries) {
      const verify = e.verifyOutcome ? ` (${e.verifyOutcome})` : "";
      lines.push(
        `| ${e.entry.package}@${e.entry.forcedVersion} | ${e.statuses.join(" + ")}${verify} | ${e.suggestedAction} |`,
      );
    }
    lines.push("");
  }

  const withChains = report.entries.filter(
    (e) => (e.roots?.length ?? 0) > 0 || (e.chains?.length ?? 0) > 0 || (e.installedVersions?.length ?? 0) > 0,
  );
  if (withChains.length) {
    lines.push("## Dependency chains", "");
    for (const e of withChains) {
      const installed = e.installedVersions?.join(", ") || "—";
      lines.push(`### ${e.entry.package}@${e.entry.forcedVersion}`, "");
      lines.push(`- **Lockfile:** ${installed} (forced: ${e.entry.forcedVersion})`);
      lines.push(`- **Roots:** ${e.roots?.join(", ") || "—"}`);
      for (const chain of e.chains ?? []) {
        lines.push(`- ${chain}`);
      }
      lines.push("");
    }
  }

  return lines.join("\n");
}
