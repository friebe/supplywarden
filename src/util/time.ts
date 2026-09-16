import type { DateLocale } from "../types.js";

export function nowIso(date = new Date()): string {
  return date.toISOString();
}

export function addDaysIso(days: number, from = new Date()): string {
  const d = new Date(from);
  d.setUTCDate(d.getUTCDate() + days);
  return d.toISOString();
}

export function isPast(iso: string, now = new Date()): boolean {
  return new Date(iso).getTime() < now.getTime();
}

export function daysOverdue(iso: string, now = new Date()): number {
  return Math.floor((now.getTime() - new Date(iso).getTime()) / 86_400_000);
}

export const DEFAULT_TIME_ZONE = "Europe/Berlin";

export function parseDateLocale(value: unknown): DateLocale {
  const raw = String(value ?? "de").trim().toLowerCase();
  if (raw === "en" || raw === "english" || raw.startsWith("en-")) return "en";
  return "de";
}

export function parseTimeZone(value: unknown): string {
  const tz = typeof value === "string" && value.trim() ? value.trim() : DEFAULT_TIME_ZONE;
  try {
    new Intl.DateTimeFormat("en", { timeZone: tz }).format(new Date());
    return tz;
  } catch {
    return DEFAULT_TIME_ZONE;
  }
}

/** Display dates in CLI/HTML. Metadata stays ISO. Default: de + Europe/Berlin. */
export function formatDisplayDate(
  iso: string | undefined | null,
  opts: { dateLocale?: DateLocale; timeZone?: string } = {},
): string {
  if (!iso) return "—";
  const date = new Date(iso);
  if (Number.isNaN(date.getTime())) return iso;
  const dateLocale = opts.dateLocale === "en" ? "en" : "de";
  const timeZone = parseTimeZone(opts.timeZone);
  const english = dateLocale === "en";
  try {
    const formatted = new Intl.DateTimeFormat(english ? "en-US" : "de-DE", {
      day: english ? "numeric" : "2-digit",
      month: english ? "short" : "2-digit",
      year: "numeric",
      hour: english ? "numeric" : "2-digit",
      minute: "2-digit",
      hour12: english,
      timeZone,
    }).format(date);
    return formatted.replace(/\u202f/g, " ").replace(/\u00a0/g, " ");
  } catch {
    return iso;
  }
}

