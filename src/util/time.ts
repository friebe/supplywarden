export function nowIso(date = new Date()): string {
  return date.toISOString();
}

/** Display dates in CLI/HTML using the machine locale and clock. Stored values stay ISO. */
export function formatDisplayDate(iso: string | undefined | null): string {
  if (!iso) return "—";
  const date = new Date(iso);
  if (Number.isNaN(date.getTime())) return iso;
  try {
    return new Intl.DateTimeFormat(undefined, {
      day: "2-digit",
      month: "2-digit",
      year: "numeric",
      hour: "2-digit",
      minute: "2-digit",
    })
      .format(date)
      .replace(/\u202f/g, " ")
      .replace(/\u00a0/g, " ");
  } catch {
    return iso;
  }
}
