import type { CheckEntry } from "../types.js";

/** Copy-paste CLI for an HTML/markdown action cell. Status wins over stale suggestedAction prose. */
export function nextCommands(e: CheckEntry): string[] {
  const pkg = e.entry.package;
  const st = e.statuses.length ? e.statuses : [e.status];
  if (st.includes("NEW") || e.weakOverride) return ["supplywarden fix --apply"];
  if (st.includes("UNTRACKED")) {
    const cmds = ["supplywarden init"];
    if (st.includes("REMOVABLE") || st.includes("RESOLVED")) {
      cmds.push(`supplywarden verify ${pkg} --apply`);
    }
    return cmds;
  }
  if (st.includes("DRIFT")) return ["supplywarden sync"];
  if (st.includes("PENDING_VERIFY")) return ["npm install"];
  if (st.includes("VERIFY_FAILED") || e.verifyOutcome === "VERIFY_FAILED") {
    return [`supplywarden why ${pkg}`];
  }
  if (e.verifyOutcome === "KEEP") {
    if (e.weakOverride) return ["supplywarden fix --apply"];
    return [`supplywarden why ${pkg}`];
  }
  if (e.verifyOutcome === "CONFIRMED_REMOVABLE") {
    return [`supplywarden verify ${pkg} --apply`];
  }
  if (st.includes("REMOVABLE") || st.includes("RESOLVED")) {
    return [`supplywarden verify ${pkg} --apply`];
  }
  if (pkg) return [`supplywarden why ${pkg}`];
  return [];
}

export function rewriteLegacyAction(text: string, pkg: string): string {
  return text
    .replaceAll("supplywarden check --apply", `supplywarden verify ${pkg} --apply`)
    .replaceAll("supplywarden verify --apply", `supplywarden verify ${pkg} --apply`)
    .replace(/supplywarden analyze(?: --audit)?/g, "supplywarden fix --apply")
    .replace(/supplywarden fix \S+ --apply --yes/g, "supplywarden fix --apply")
    .replace(/ --yes\b/g, "")
    .replace(/supplywarden verify(?! \S)/g, `supplywarden verify ${pkg}`);
}

export function withReportCommands(entry: CheckEntry): CheckEntry {
  return {
    ...entry,
    suggestedAction: rewriteLegacyAction(entry.suggestedAction, entry.entry.package),
    commands: nextCommands(entry),
  };
}
