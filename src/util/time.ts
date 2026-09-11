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
