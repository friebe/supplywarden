import { maxSeverity } from "../alerts/dependabot.js";
import { stillVulnerable } from "../decision/engine.js";
import { advisoriesAtSeverity } from "../registry/advisories.js";
import { versionSatisfiesSpec } from "../util/semver-spec.js";
import type { Advisory, Depender, OverrideScope, Severity } from "../types.js";

export type PlannedParent = {
  parent: string;
  pin: string;
  /** Undefined when the range could not be resolved without installing. */
  natural: string | undefined;
};

export type OverrideJudgment = {
  action: "keep" | "drop";
  summary: string;
  advisories: Advisory[];
  severity: Severity;
};

/**
 * Which parents this override still changes. A scoped pin only covers its parent.
 * A global pin covers every parent that still depends on the package.
 */
export async function planParents(opts: {
  pins: Array<{ version: string; scope: OverrideScope }>;
  dependers: Depender[];
  resolveRange: (range: string) => Promise<string | undefined>;
}): Promise<PlannedParent[] | null> {
  const global = opts.pins.find((pin) => pin.scope.type === "global");
  const scoped = new Map<string, string>();
  for (const pin of opts.pins) {
    if (pin.scope.type === "scoped") scoped.set(pin.scope.parent, pin.version);
  }
  const affected = opts.dependers.flatMap((depender) => {
    const pin = scoped.get(depender.parent) ?? global?.version;
    return pin ? [{ parent: depender.parent, range: depender.range, pin }] : [];
  });
  if (!affected.length) return null;
  return Promise.all(
    affected.map(async (row) => ({
      parent: row.parent,
      pin: row.pin,
      natural: await opts.resolveRange(row.range),
    })),
  );
}

/**
 * `advisories` is null when this run has no advisory lookup. A missing map entry
 * means the lookup failed. An empty list means that version is clean.
 */
export function judgeParents(opts: {
  pkg: string;
  version: string;
  parents: PlannedParent[] | null;
  advisories: ReadonlyMap<string, Advisory[] | undefined> | null;
  minSeverity: Severity;
}): OverrideJudgment {
  if (!opts.parents) {
    return keep(opts.pkg, opts.version, "The override could not be matched to a parent in the lockfile.");
  }
  if (opts.parents.some((parent) => !parent.natural)) {
    return keep(
      opts.pkg,
      opts.version,
      "The version parents would install without it could not be resolved.",
    );
  }
  const resolved = opts.parents as Array<PlannedParent & { natural: string }>;
  const held = resolved.filter((parent) => !versionSatisfiesSpec(parent.natural, parent.pin));
  if (!held.length) {
    return {
      action: "drop",
      summary: `Override ${label(opts.pkg, resolved[0]!.pin)} is no longer required. ${resolvesTo(resolved)}.`,
      advisories: [],
      severity: "unknown",
    };
  }
  if (!opts.advisories) {
    return keep(
      opts.pkg,
      opts.version,
      "The advisory list for the version parents would install was not available.",
    );
  }
  const vulnerable: Array<PlannedParent & { natural: string }> = [];
  const found: Advisory[] = [];
  for (const parent of held) {
    const list = opts.advisories.get(`${opts.pkg}@${parent.natural}`);
    if (!list) {
      return keep(
        opts.pkg,
        opts.version,
        "The advisory list for the version parents would install could not be checked.",
      );
    }
    const relevant = advisoriesAtSeverity(list, opts.minSeverity).filter((advisory) =>
      stillVulnerable(parent.natural, [advisory]),
    );
    if (relevant.length) {
      vulnerable.push(parent);
      found.push(...relevant);
    }
  }
  if (vulnerable.length) {
    return {
      action: "keep",
      summary: `Override ${label(opts.pkg, vulnerable[0]!.pin)} is still required. Without it, ${sentence(vulnerable)}, which is still vulnerable.`,
      advisories: dedupeAdvisories(found),
      severity: maxSeverity(found),
    };
  }
  return {
    action: "drop",
    summary: `Override ${label(opts.pkg, held[0]!.pin)} is no longer required. Without it, ${sentence(held)}, which is outside the advisory.`,
    advisories: [],
    severity: "unknown",
  };
}

function keep(pkg: string, version: string, why: string): OverrideJudgment {
  return {
    action: "keep",
    summary: `Override ${pkg}@${version} stays. ${why}`,
    advisories: [],
    severity: "unknown",
  };
}

function label(pkg: string, version: string): string {
  return `${pkg}@${version}`;
}

function resolvesTo(parents: Array<{ parent: string; natural: string }>): string {
  return groupParents(parents)
    .map(([version, names]) => `${joinNames(names)} already resolves to ${version}`)
    .join(", and ");
}

function sentence(parents: Array<{ parent: string; natural: string }>): string {
  return groupParents(parents)
    .map(([version, names]) => `${joinNames(names)} would install ${version}`)
    .join(", and ");
}

function groupParents(
  parents: Array<{ parent: string; natural: string }>,
): Array<[string, string[]]> {
  const byVersion = new Map<string, string[]>();
  for (const parent of parents) {
    const names = byVersion.get(parent.natural) ?? [];
    if (!names.includes(parent.parent)) names.push(parent.parent);
    byVersion.set(parent.natural, names);
  }
  return [...byVersion.entries()];
}

function joinNames(names: string[]): string {
  if (names.length <= 2) return names.join(" and ");
  if (names.length === 3) return `${names[0]}, ${names[1]} and ${names[2]}`;
  return `${names[0]}, ${names[1]}, ${names[2]} and ${names.length - 3} more`;
}

function dedupeAdvisories(advisories: Advisory[]): Advisory[] {
  const seen = new Set<string>();
  const out: Advisory[] = [];
  for (const advisory of advisories) {
    const key = advisory.ghsaId ?? advisory.cveId ?? `${advisory.vulnerableRange}:${advisory.severity}`;
    if (seen.has(key)) continue;
    seen.add(key);
    out.push(advisory);
  }
  return out;
}
