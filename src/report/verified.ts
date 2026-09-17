import type { DateLocale, MetadataEntry } from "../types.js";
import { formatDisplayDate } from "../util/time.js";

export function formatVerifiedKeep(
  entry: Pick<MetadataEntry, "resolution" | "resolvedAt" | "resolvedBy">,
  dateOpts: { dateLocale?: DateLocale; timeZone?: string } = {},
): string | undefined {
  if (!entry.resolution?.startsWith("verify-keep:")) return undefined;
  const when = formatDisplayDate(entry.resolvedAt, dateOpts);
  const who = entry.resolvedBy?.trim();
  if (who && when !== "—") return `verified ${when} ${who}`;
  if (when !== "—") return `verified ${when}`;
  if (who) return `verified ${who}`;
  return "verified";
}
