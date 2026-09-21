import type { CheckEntry, ReportModel } from "../types.js";
import { removableReasonLabel, sortCheckEntries } from "../check/classify.js";
import { nextCommands, withReportCommands } from "./commands.js";
import { formatUpgradeTarget, formatUpgradeTargets } from "../decision/engine.js";
import { formatDisplayDate, nowIso } from "../util/time.js";
import { loadConfig } from "../config.js";
import { dependencyKindLabel } from "../graph/npm.js";
import { formatVerifiedKeep } from "./verified.js";

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
  if (e.verifyOutcome === "KEEP" || e.verifyOutcome === "VERIFY_FAILED") return false;
  return e.statuses.includes("REMOVABLE") || e.statuses.includes("RESOLVED");
}

export function toMarkdown(report: ReportModel): string {
  const dateOpts = dateOptsFrom(report);
  const lines: string[] = [`# ${report.title}`, ""];
  lines.push(`Generated: ${formatDisplayDate(report.generatedAt, dateOpts)}`, "");
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
      if (group.dependencyKind && group.dependencyKind !== "production") {
        lines.push(`**Tree:** ${group.dependencyKind} only`, "");
      }
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

  const entries = sortCheckEntries(report.entries).map(withReportCommands);
  const news = entries.filter((e) => e.status === "NEW" || e.statuses.includes("NEW"));
  if (news.length) {
    lines.push("## New", "");
    for (const e of news) {
      const installed = e.installedVersions?.join(", ") || "—";
      lines.push(`- **${e.entry.package}** (lockfile ${installed})`);
      if (e.decision?.strategy === "upgrade") {
        const targets = (e.decision.upgradeTargets ?? []).filter((t) => t.to);
        for (const t of targets) {
          lines.push(`  - ${formatUpgradeTarget(t)}`);
        }
        if (!targets.length) {
          const bump = formatUpgradeTargets(e.decision);
          if (bump) lines.push(`  - ${bump}`);
        }
      } else if (e.decision?.strategy === "wait") {
        lines.push("  - WAIT — no override/upgrade this cycle");
      } else {
        lines.push(`  - OVERRIDE ${e.entry.package}@${e.decision?.forcedVersion ?? e.entry.forcedVersion}`);
      }
      for (const c of e.commands ?? nextCommands(e)) {
        lines.push(`  - \`${c}\``);
      }
    }
    lines.push("");
  }
  const removable = entries.filter(canRemove);
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

  if (entries.length) {
    lines.push(
      "| Package | Status | Scope | Recommendation | Review by |",
      "|---------|--------|-------|----------------|-----------|",
    );
    for (const e of entries) {
      const verify = e.verifyOutcome ? ` (${e.verifyOutcome})` : "";
      const extra = dependencyKindLabel(e.dependencyKind);
      const extraMark = extra ? ` · ${extra}` : "";
      const scope = e.dependencyKind ?? "—";
      const cmd = (e.commands ?? nextCommands(e)).map((c) => `\`${c}\``).join(" · ");
      const upgrade = formatUpgradeTargets(e.decision);
      const rec = [upgrade, cmd || e.suggestedAction].filter(Boolean).join(" · ");
      const verified = e.verifiedNote ?? formatVerifiedKeep(e.entry, dateOpts);
      const verifiedMark = verified ? ` · ${verified}` : "";
      lines.push(
        `| ${e.entry.package}@${e.entry.forcedVersion}${extraMark} | ${e.statuses.join(" + ")}${verify}${verifiedMark} | ${scope} | ${rec} | ${formatDisplayDate(e.entry.reviewBy, dateOpts)} |`,
      );
    }
    lines.push("");
  }

  const withChains = entries.filter(
    (e) => (e.roots?.length ?? 0) > 0 || (e.chains?.length ?? 0) > 0 || (e.installedVersions?.length ?? 0) > 0,
  );
  if (withChains.length) {
    lines.push("## Dependency chains", "");
    for (const e of withChains) {
      const installed = e.installedVersions?.join(", ") || "—";
      lines.push(`### ${e.entry.package}@${e.entry.forcedVersion}`, "");
      lines.push(`- **Lockfile:** ${installed} (forced: ${e.entry.forcedVersion})`);
      if (e.dependerRanges?.length) {
        lines.push(
          `- **Dependents asked for (lockfile specs, not installed):** ${e.dependerRanges.join(", ")}`,
        );
      }
      lines.push(`- **Roots:** ${e.roots?.join(", ") || "—"}`);
      if (e.dependencyKind && e.dependencyKind !== "production") {
        lines.push(`- **Tree:** ${e.dependencyKind} only`);
      }
      for (const chain of e.chains ?? []) {
        lines.push(`- ${chain}`);
      }
      lines.push("");
    }
  }

  return lines.join("\n");
}

function dateOptsFrom(report: ReportModel): { dateLocale: "de" | "en"; timeZone: string } {
  const config = report.cwd ? loadConfig(report.cwd) : undefined;
  return {
    dateLocale: report.dateLocale ?? config?.dateLocale ?? "de",
    timeZone: report.timeZone ?? config?.timeZone ?? "Europe/Berlin",
  };
}
