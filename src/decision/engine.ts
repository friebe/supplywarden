import { compare, major, minVersion, satisfies, valid, gt } from "semver";
import type {
  Advisory,
  Decision,
  DependencyChain,
  DependencyKind,
  Depender,
  GraphAnalysis,
  OverrideScope,
  RootPackage,
  RegistryClient,
  Severity,
  Strategy,
  SupplywardenConfig,
  UpgradeTarget,
} from "../types.js";
import { inferSafeFloorFromVulnerableRange } from "../util/vuln-range.js";

export type UpgradeLookup = {
  latestVersion?: (pkg: string) => Promise<string | undefined>;
  getLatestMatching?: (pkg: string, range: string) => Promise<string | undefined>;
  versionsNewerThan?: (pkg: string, from: string) => Promise<string[] | undefined>;
  dependencyRange?: (pkg: string, version: string, dep: string) => Promise<string | undefined>;
  minMatching?: (pkg: string, range: string) => Promise<string | undefined>;
  peerDependencies?: (pkg: string, version: string) => Promise<Record<string, string> | undefined>;
};

export type UpgradeProofContext = {
  vulnPackage: string;
  advisories: Advisory[];
  chains: DependencyChain[];
  dependers?: Depender[];
  dependencyKind?: DependencyKind;
  directs?: Array<{ name: string; version: string }>;
  /** When false, a non-critical dev or optional tree goes to triage instead of pinning. Default: pin. */
  pinDevelopment?: boolean;
  /** Roots/parents above this count go to triage instead of an automatic upgrade or override. */
  threshold?: number;
};

export function recommend(input: {
  rootCount: number;
  threshold: number;
  canUpgradeRoots: boolean;
  kind?: DependencyKind;
  severity?: Severity;
  pinDevelopment?: boolean;
}): Strategy {
  if (input.canUpgradeRoots && input.rootCount <= input.threshold) return "upgrade";
  if (shouldTriageDevelopment(input.kind, input.severity, input.pinDevelopment !== false)) {
    return "triage";
  }
  return "override";
}

/** Dev/optional trees go to triage only when `pinDevelopment` is off, and never for a critical advisory. */
export function shouldTriageDevelopment(
  kind?: DependencyKind,
  severity?: Severity,
  pinDevelopment = true,
): boolean {
  if (pinDevelopment) return false;
  if (severity === "critical") return false;
  return kind === "development" || kind === "optional";
}

function maxAdvisorySeverity(advisories: Advisory[]): Severity {
  let best: Severity = "unknown";
  const rank: Record<Severity, number> = { critical: 4, high: 3, medium: 2, low: 1, unknown: 0 };
  for (const advisory of advisories) {
    if (rank[advisory.severity] > rank[best]) best = advisory.severity;
  }
  return best;
}

export function decide(opts: {
  graph: GraphAnalysis;
  advisories: Advisory[];
  config: SupplywardenConfig;
}): Decision {
  const forcedVersion = firstSafeForcedVersion(opts.advisories);
  const refreshable =
    forcedVersion && canRefreshTransitive(opts.graph, opts.advisories, forcedVersion);
  const rootCount = opts.graph.roots.length || 1;
  const kind = opts.graph.dependencyKind;
  const severity = maxAdvisorySeverity(opts.advisories);
  const threshold = opts.config.upgradeRootThreshold;
  const canUpgrade = Boolean(forcedVersion) && rootCount <= threshold;
  const strategy = recommend({
    rootCount,
    threshold,
    canUpgradeRoots: canUpgrade,
    kind,
    severity,
    pinDevelopment: opts.config.pinDevelopment,
  });

  const scopes = overrideScopes(opts.graph, opts.advisories);
  const scope = scopes[0] ?? { type: "global" as const };

  const tree =
    kind === "development" || kind === "optional" ? `${kind} dependency` : "production dependency";

  if (refreshable) {
    return {
      strategy: "refresh",
      reason: `${forcedVersion} satisfies every immediate parent range. Refresh the lockfile before changing a root or writing an override.`,
      forcedVersion,
      scope,
      scopes,
    };
  }

  if (strategy === "upgrade") {
    return {
      strategy: "upgrade",
      reason: `${rootCount} root(s), at or under the threshold of ${threshold}. Upgrade the root before pinning.`,
      forcedVersion,
      scope,
      scopes,
      upgradeTargets: opts.graph.roots.map((r) => ({
        name: r.name,
        from: r.version,
        ...(r.importer ? { filter: r.importer } : {}),
        ...(r.catalog ? { catalog: r.catalog } : {}),
      })),
    };
  }

  if (strategy === "triage") {
    const count =
      rootCount > threshold
        ? `${rootCount} roots, more than the threshold of ${threshold}.`
        : `${rootCount} root(s).`;
    const patch = forcedVersion ? "" : " The advisory names no patched version.";
    return {
      strategy: "triage",
      reason: `${count} This is a ${tree}, severity ${severity}, not critical.${patch} No root upgrade and no pin.`,
      forcedVersion,
      scope,
      scopes,
    };
  }

  // strategy === "override": only write it automatically when it is non-breaking and scoped to
  // few enough parents to stay a deliberate, countable pin instead of silent sprawl.
  if (forcedVersion) {
    const gate = overrideGate({
      scopes,
      installedVersions: opts.graph.versions,
      forcedVersion,
      pkg: opts.graph.package,
      threshold,
    });
    if (gate.blocked) {
      return {
        strategy: "triage",
        reason: overrideTriageReason({
          pkg: opts.graph.package,
          forcedVersion,
          scopes,
          dependers: opts.graph.dependers,
          installedVersions: opts.graph.versions,
          breaking: gate.breaking,
          affected: gate.affected,
          threshold,
        }),
        forcedVersion,
        scope,
        scopes,
      };
    }
  }

  const why = !forcedVersion
    ? "The advisory names no patched version, so there is nothing safe to pin."
    : rootCount > threshold
      ? `${rootCount} roots, more than the threshold of ${threshold}. A root upgrade is not attempted.`
      : `${rootCount} root(s), at or under the threshold of ${threshold}, and a root upgrade is not available.`;
  return {
    strategy: "override",
    reason: forcedVersion ? `${why} ${pinLabel(opts.graph.package, forcedVersion, scopes)}` : why,
    forcedVersion,
    scope,
    scopes,
  };
}

function canRefreshTransitive(
  graph: GraphAnalysis,
  advisories: Advisory[],
  forcedVersion: string,
): boolean {
  const vulnerableDirect = graph.roots.some(
    (root) => root.name === graph.package && stillVulnerable(root.version, advisories),
  );
  const vulnerableParents = new Set(
    graph.chains
      .filter((chain) => stillVulnerable(chain.version, advisories) && chain.path.length > 1)
      .map((chain) => stripVersion(chain.path[chain.path.length - 2]!)),
  );
  const dependers = graph.dependers?.filter((depender) => vulnerableParents.has(depender.parent));
  return (
    !vulnerableDirect &&
    Boolean(dependers?.length) &&
    dependers!.every((depender) => rangeAccepts(depender.range, forcedVersion))
  );
}

/**
 * Gate on whether an override is safe to write automatically: it stays within the installed
 * major version, and it is scoped to few enough parents that it stays a deliberate, countable
 * pin instead of silent sprawl. A same-major pin past an exact or narrow parent range (the
 * ordinary reason `overrides` exists at all) still passes — only a major jump, or fragmenting
 * across too many parents, goes to triage, where a human decides to accept the risk, wait for
 * upstream, or write the override by hand.
 */
function overrideGate(opts: {
  scopes: OverrideScope[];
  installedVersions: string[];
  forcedVersion: string;
  pkg: string;
  threshold: number;
}): { blocked: boolean; breaking: boolean; affected: number } {
  const breaking = Boolean(breakingPinSummary(opts.pkg, opts.installedVersions, opts.forcedVersion));
  const affected = opts.scopes.length;
  return { blocked: breaking || affected > opts.threshold, breaking, affected };
}

/** Explains why an override was sent to triage instead of written, reusing the same diagnostics as the written-pin warnings. */
function overrideTriageReason(opts: {
  pkg: string;
  forcedVersion: string;
  scopes: OverrideScope[];
  dependers: Depender[] | undefined;
  installedVersions: string[];
  breaking: boolean;
  affected: number;
  threshold: number;
}): string {
  const tail =
    "This needs a human decision: accept the risk, wait for upstream, or write the override manually.";
  if (!opts.breaking) {
    return `${opts.affected} override(s) would be needed, more than the threshold of ${opts.threshold}. ${tail}`;
  }
  const isGlobal = opts.scopes.some((s) => s.type === "global");
  if (!isGlobal) {
    const rejection = rangeRejectionNote({
      pkg: opts.pkg,
      version: opts.forcedVersion,
      dependers: opts.dependers,
      strategy: "override",
    });
    if (rejection) return `${rejection} ${tail}`;
  }
  const pinNote = breakingPinNote(opts.pkg, opts.installedVersions, opts.forcedVersion);
  return `${pinNote ?? `Pinning ${opts.pkg}@${opts.forcedVersion} would cross a major version boundary.`} ${tail}`;
}

export function formatUpgradeTarget(t: {
  name: string;
  from?: string;
  to?: string;
  skipped?: string[];
}): string {
  const skip = formatSkipped(t.skipped);
  if (t.to && t.from && t.to !== t.from) return `${t.name}@${t.from} → ${t.to}${skip}`;
  if (t.to) return `${t.name} → ${t.to}${skip}`;
  if (t.from) return `${t.name} (installed ${t.from}; need a newer release)`;
  return t.name;
}

function formatSkipped(skipped?: string[]): string {
  if (!skipped?.length) return "";
  const shown = skipped.slice(0, 3);
  const more = skipped.length > shown.length ? ` +${skipped.length - shown.length}` : "";
  return ` (not ${shown.join(", ")}${more} — still vulnerable)`;
}

/** `from → to` when the two versions are different majors, otherwise undefined. */
export function majorJumpLabel(from?: string, to?: string): string | undefined {
  if (!from || !to || !valid(from) || !valid(to)) return undefined;
  if (major(from) === major(to)) return undefined;
  return `${from} → ${to}`;
}

/** Proven root upgrades that cross a major, e.g. `express@4.18.2 → 5.0.0`. */
export function breakingUpgradeSummary(decision?: Decision): string {
  if (!decision?.upgradeTargets?.length) return "";
  return decision.upgradeTargets
    .map((t) => {
      const jump = t.to ? majorJumpLabel(t.from, t.to) : undefined;
      return jump ? `${t.name}@${jump}` : undefined;
    })
    .filter((label): label is string => Boolean(label))
    .join(", ");
}

export function breakingUpgradeNote(decision?: Decision): string | undefined {
  const summary = breakingUpgradeSummary(decision);
  if (!summary) return undefined;
  return `No override written. The advisory only closes with a breaking major upgrade: ${summary}. package.json was left unchanged.`;
}

function majorPinLabels(
  pkg: string,
  installed: string[],
  forced: string,
  direction: "up" | "down",
): string {
  return installed
    .filter((version) => {
      if (!majorJumpLabel(version, forced)) return false;
      const fromMajor = major(version);
      const toMajor = major(forced);
      return direction === "up" ? fromMajor < toMajor : fromMajor > toMajor;
    })
    .map((version) => `${pkg}@${version} → ${forced}`)
    .join(", ");
}

/** Installed copies the pin would move onto another major. */
export function breakingPinSummary(pkg: string, installed: string[], forced?: string): string {
  if (!forced) return "";
  return [
    majorPinLabels(pkg, installed, forced, "up"),
    majorPinLabels(pkg, installed, forced, "down"),
  ]
    .filter(Boolean)
    .join(", ");
}

export function breakingPinNote(
  pkg: string,
  installed: string[],
  forced?: string,
): string | undefined {
  if (!forced) return undefined;
  const up = majorPinLabels(pkg, installed, forced, "up");
  const down = majorPinLabels(pkg, installed, forced, "down");
  const notes: string[] = [];
  if (up) notes.push(`Breaking major pin: ${up}. Dependents still on the old major can break.`);
  if (down) notes.push(`Breaking major pin: ${down}. Forcing an older major can break.`);
  return notes.join(" ") || undefined;
}

/** Lowest proven root version(s) that close the advisory, e.g. `nx@23.2.1 → 23.2.5`. */
export function formatUpgradeTargets(decision?: Decision): string {
  if (decision?.strategy !== "upgrade") return "";
  return (decision.upgradeTargets ?? [])
    .filter((t) => Boolean(t.to))
    .map(formatUpgradeTarget)
    .join(", ");
}

export function lookupFromRegistry(registry?: RegistryClient): UpgradeLookup {
  if (!registry) return {};
  return {
    latestVersion: registry.latestVersion?.bind(registry),
    getLatestMatching: registry.getLatestMatching?.bind(registry),
    versionsNewerThan: registry.versionsNewerThan?.bind(registry),
    dependencyRange: registry.dependencyRange?.bind(registry),
    minMatching: registry.minMatching?.bind(registry),
    peerDependencies: registry.peerDependencies?.bind(registry),
  };
}

export async function resolveUpgradeDecision(
  decision: Decision,
  lookup: UpgradeLookup = {},
  proof?: UpgradeProofContext,
): Promise<Decision> {
  if (
    proof &&
    decision.forcedVersion &&
    (await currentTreeCanRefresh(proof, decision.forcedVersion, lookup))
  ) {
    return {
      strategy: "refresh",
      reason: `${decision.forcedVersion} satisfies every immediate parent range. Refresh the lockfile before changing a root or writing an override.`,
      forcedVersion: decision.forcedVersion,
      scope: decision.scope,
      scopes: decision.scopes,
    };
  }
  if (decision.strategy === "triage") return decision;
  if (decision.strategy !== "upgrade" || !decision.upgradeTargets?.length) return decision;
  if (!hasLookup(lookup)) return decision;

  let lookedUpAny = false;
  let hadCandidate = false;
  const targets: NonNullable<Decision["upgradeTargets"]> = [];
  for (const t of decision.upgradeTargets) {
    const from = t.from && valid(t.from) ? t.from : undefined;
    const { versions, lookedUp } = await candidateVersions(t.name, from, lookup);
    if (lookedUp) lookedUpAny = true;
    if (versions.length) hadCandidate = true;
    let to: string | undefined;
    const skipped: string[] = [];
    if (proof) {
      for (const version of preferSameMajor(from, versions)) {
        if (await rootVersionClosesVuln(t.name, version, proof, lookup)) {
          to = version;
          break;
        }
        skipped.push(version);
      }
    }
    targets.push({ ...t, to, skipped: skipped.length ? skipped : undefined });
  }

  if (targets.every((t) => Boolean(t.to)) && proof) {
    return withPeerCompanions(
      { ...decision, upgradeTargets: targets },
      proof.directs ?? [],
      lookup,
    );
  }

  if (lookedUpAny && decision.forcedVersion) {
    const installed = targets.map((t) => `${t.name}@${t.from ?? "?"}`).join(", ");
    const kind = proof?.dependencyKind;
    const severity = proof ? maxAdvisorySeverity(proof.advisories) : undefined;
    if (shouldTriageDevelopment(kind, severity, proof?.pinDevelopment !== false)) {
      return {
        strategy: "triage",
        reason: `${installed} has no published version that closes ${proof?.vulnPackage ?? "the advisory"}. ${kind ?? "non-production"} dependency, not critical — no pin.`,
        forcedVersion: decision.forcedVersion,
        scope: decision.scope,
        scopes: decision.scopes,
      };
    }
    const scopes = decision.scopes ?? [decision.scope];
    const installedVersions = [
      ...new Set(
        (proof?.chains ?? [])
          .filter((chain) => chain.package === proof?.vulnPackage)
          .map((chain) => chain.version),
      ),
    ];
    const gate = overrideGate({
      scopes,
      installedVersions,
      forcedVersion: decision.forcedVersion,
      pkg: proof?.vulnPackage ?? "it",
      threshold: proof?.threshold ?? Infinity,
    });
    if (gate.blocked) {
      const base = hadCandidate
        ? `${installed} has no published version that closes ${proof?.vulnPackage ?? "the advisory"}.`
        : `${installed} is already the latest published version, so a root upgrade cannot go higher.`;
      const reason = `${base} ${overrideTriageReason({
        pkg: proof?.vulnPackage ?? "it",
        forcedVersion: decision.forcedVersion,
        scopes,
        dependers: proof?.dependers,
        installedVersions,
        breaking: gate.breaking,
        affected: gate.affected,
        threshold: proof?.threshold ?? Infinity,
      })}`;
      return {
        strategy: "triage",
        reason,
        forcedVersion: decision.forcedVersion,
        scope: decision.scope,
        scopes: decision.scopes,
      };
    }
    const pin = pinLabel(proof?.vulnPackage ?? "it", decision.forcedVersion, scopes);
    const reason = hadCandidate
      ? `${installed} has no published version that closes ${proof?.vulnPackage ?? "the advisory"}. ${pin}`
      : `${installed} is already the latest published version, so a root upgrade cannot go higher. ${pin}`;
    return {
      strategy: "override",
      reason,
      forcedVersion: decision.forcedVersion,
      scope: decision.scope,
      scopes: decision.scopes,
    };
  }

  return { ...decision, upgradeTargets: targets };
}

async function currentTreeCanRefresh(
  proof: UpgradeProofContext,
  forcedVersion: string,
  lookup: UpgradeLookup,
): Promise<boolean> {
  if (!lookup.dependencyRange) return false;
  const parents = new Map<string, { name: string; version: string }>();
  for (const chain of proof.chains) {
    if (!stillVulnerable(chain.version, proof.advisories)) continue;
    if (chain.path.length < 2) return false;
    const parent = parseSegment(chain.path[chain.path.length - 2]!);
    if (!parent) return false;
    parents.set(`${parent.name}\0${parent.version}`, parent);
  }
  if (!parents.size) return false;
  for (const parent of parents.values()) {
    const publishedRange = await lookup.dependencyRange(
      parent.name,
      parent.version,
      proof.vulnPackage,
    );
    const knownRange = proof.dependers?.find(
      (depender) => depender.parent === parent.name && depender.version === parent.version,
    )?.range;
    const range = publishedRange ?? knownRange;
    if (!range || !rangeAccepts(range, forcedVersion)) return false;
  }
  return true;
}

function parseSegment(segment: string): { name: string; version: string } | undefined {
  const at = segment.lastIndexOf("@");
  if (at <= 0 || at === segment.length - 1) return undefined;
  return { name: segment.slice(0, at), version: segment.slice(at + 1) };
}

function hasLookup(lookup: UpgradeLookup): boolean {
  return Boolean(
    lookup.latestVersion ||
    lookup.getLatestMatching ||
    lookup.versionsNewerThan ||
    lookup.dependencyRange,
  );
}

async function candidateVersions(
  name: string,
  from: string | undefined,
  lookup: UpgradeLookup,
): Promise<{ versions: string[]; lookedUp: boolean }> {
  if (from && lookup.versionsNewerThan) {
    const raw = await lookup.versionsNewerThan(name, from);
    if (raw === undefined) return { versions: [], lookedUp: false };
    const versions = raw.filter((version) => valid(version) && gt(version, from));
    return { versions, lookedUp: true };
  }

  const sameMajorRange = from !== undefined ? `>${from} <${major(from) + 1}.0.0` : undefined;
  const latestSameMajor = sameMajorRange
    ? await lookup.getLatestMatching?.(name, sameMajorRange)
    : undefined;
  const latestOverall =
    (await lookup.latestVersion?.(name)) ?? (await lookup.getLatestMatching?.(name, "*"));
  const lookedUp = latestSameMajor !== undefined || latestOverall !== undefined;
  const versions = uniqueNewer(from, [latestSameMajor, latestOverall]);
  return { versions, lookedUp };
}

function uniqueNewer(from: string | undefined, raw: Array<string | undefined>): string[] {
  const out: string[] = [];
  for (const version of raw) {
    if (!version || !valid(version)) continue;
    if (from && valid(from) && !gt(version, from)) continue;
    if (!out.includes(version)) out.push(version);
  }
  return out;
}

function preferSameMajor(from: string | undefined, versions: string[]): string[] {
  const same: string[] = [];
  const other: string[] = [];
  for (const version of versions) {
    if (from && valid(from) && valid(version) && major(version) === major(from)) same.push(version);
    else other.push(version);
  }
  same.sort(compare);
  other.sort(compare);
  return [...same, ...other];
}

async function rootVersionClosesVuln(
  rootName: string,
  rootVersion: string,
  proof: UpgradeProofContext,
  lookup: UpgradeLookup,
): Promise<boolean> {
  if (rootName === proof.vulnPackage) {
    return !stillVulnerable(rootVersion, proof.advisories);
  }

  const chains = proof.chains.filter((chain) => stripVersion(chain.path[0] ?? "") === rootName);
  const namesList = chains.length
    ? chains.map((chain) => chain.path.map(stripVersion))
    : [[rootName, proof.vulnPackage]];

  for (const names of namesList) {
    if (!(await chainCloses(rootName, rootVersion, names, proof, lookup))) return false;
  }
  return namesList.length > 0;
}

async function chainCloses(
  rootName: string,
  rootVersion: string,
  names: string[],
  proof: UpgradeProofContext,
  lookup: UpgradeLookup,
): Promise<boolean> {
  const rootIdx = names.indexOf(rootName);
  const vulnIdx = names.lastIndexOf(proof.vulnPackage);
  if (rootIdx < 0 || vulnIdx <= rootIdx) return false;

  let pkg = rootName;
  let version = rootVersion;
  for (let i = rootIdx + 1; i <= vulnIdx; i++) {
    const next = names[i]!;
    const range = await lookup.dependencyRange?.(pkg, version, next);
    if (!range) return false;
    if (i === vulnIdx) return rangeFloorSafe(range, proof.advisories);
    const hop = (await lookup.minMatching?.(next, range)) ?? rangeMinVersion(range);
    if (!hop || !valid(hop)) return false;
    pkg = next;
    version = hop;
  }
  return false;
}

function rangeFloorSafe(spec: string, advisories: Advisory[]): boolean {
  const min = rangeMinVersion(spec);
  return Boolean(min && !stillVulnerable(min, advisories));
}

function rangeMinVersion(spec: string): string | undefined {
  try {
    return minVersion(spec.replace(/^npm:/, "").trim())?.version;
  } catch {
    return undefined;
  }
}

function copyStillVulnerable(version: string | undefined, advisories?: Advisory[]): boolean {
  if (!advisories) return true;
  if (!version || version === "?") return true;
  return stillVulnerable(version, advisories);
}

/** Roots and chains whose installed copy is still inside the advisory. A safe copy stays out of Via. */
export function vulnerableReach(
  graph: GraphAnalysis,
  advisories: Advisory[],
): { roots: RootPackage[]; chains: DependencyChain[] } {
  const chains = graph.chains.filter((chain) => stillVulnerable(chain.version, advisories));
  if (!chains.length) return { roots: graph.roots, chains: graph.chains };
  const names = new Set(
    chains.map((chain) => stripVersion(chain.path[0] ?? "")).filter((name) => name.length > 0),
  );
  const roots = graph.roots.filter((root) => names.has(root.name));
  return { roots: roots.length ? roots : graph.roots, chains };
}

/** One scoped pin per parent that still pulls a vulnerable copy. A vulnerable direct dependency stays a global pin. */
export function overrideScopes(graph: GraphAnalysis, advisories?: Advisory[]): OverrideScope[] {
  const parents = new Set<string>();
  let directVulnerable = graph.roots.some(
    (root) => root.name === graph.package && copyStillVulnerable(root.version, advisories),
  );
  for (const chain of graph.chains) {
    const names = chain.path.map((segment) => stripVersion(segment));
    const idx = names.lastIndexOf(graph.package);
    if (idx <= 0) {
      if (copyStillVulnerable(chain.version, advisories)) directVulnerable = true;
      continue;
    }
    if (!copyStillVulnerable(chain.version, advisories)) continue;
    const parent = names[idx - 1];
    if (parent) parents.add(parent);
  }
  if (directVulnerable || parents.size === 0) return [{ type: "global" }];
  return [...parents].sort().map((parent) => ({ type: "scoped", parent }));
}

/** The installed direct copy is already outside the advisory, so the pin must not move it. */
export function safeDirectCopyNote(
  graph: GraphAnalysis,
  advisories: Advisory[],
  scopes: OverrideScope[],
): string | undefined {
  if (scopes.some((scope) => scope.type === "global")) return undefined;
  const version = graph.roots.find((root) => root.name === graph.package)?.version;
  if (!version || version === "?" || stillVulnerable(version, advisories)) return undefined;
  return `${graph.package}@${version} is already outside the advisory.`;
}

export function pinLabel(pkg: string, version: string, scopes: OverrideScope[]): string {
  const parents = scopes.flatMap((scope) => (scope.type === "scoped" ? [scope.parent] : []));
  if (!parents.length) return `Pin ${pkg}@${version}.`;
  return `Pin ${pkg}@${version} under ${parents.join(" and ")}.`;
}

/** A pin the human can consciously force-write from triage, including optional version selectors. */
export type ProposedOverridePin = {
  package: string;
  version: string;
  scope: OverrideScope;
  /** npm/pnpm override key suffix after `pkg@`, e.g. `">=7 <11.0.1"`. */
  selector?: string;
};

export type TriageOverrideProposal = {
  /** Compact JSON snippets for the summary, e.g. `"uuid@>=9 <11.1.1": "11.1.1"`. */
  entries: string[];
  pins: ProposedOverridePin[];
  forceCommand: string;
};

/**
 * Range that remaps only the vulnerable majors jumping up to `forced`, leaving older
 * lines outside the selector untouched — e.g. `">=7 <11.0.1"` for minimatch.
 */
export function majorJumpSelectorRange(
  installedVersions: string[],
  advisories: Advisory[],
  forced: string,
): string | undefined {
  if (!valid(forced)) return undefined;
  const toMajor = major(forced);
  const fromMajors = installedVersions
    .filter(
      (version) =>
        valid(version) && stillVulnerable(version, advisories) && major(version) < toMajor,
    )
    .map((version) => major(version));
  if (!fromMajors.length) return undefined;
  const minFrom = Math.min(...fromMajors);
  if (minFrom >= toMajor) return undefined;
  return `>=${minFrom} <${forced}`;
}

function formatProposedPin(pin: ProposedOverridePin): string {
  const key = pin.selector ? `${pin.package}@${pin.selector}` : pin.package;
  if (pin.scope.type === "scoped") {
    return `"${pin.scope.parent}": { "${key}": "${pin.version}" }`;
  }
  return `"${key}": "${pin.version}"`;
}

/**
 * Concrete override the human can force from triage. Major jumps prefer a version
 * selector so older major lines stay untouched; otherwise the usual scoped/global pins.
 */
export function proposeTriageOverride(opts: {
  pkg: string;
  version: string;
  scopes: OverrideScope[];
  installedVersions: string[];
  advisories: Advisory[];
}): TriageOverrideProposal {
  const selector = majorJumpSelectorRange(opts.installedVersions, opts.advisories, opts.version);
  const pins: ProposedOverridePin[] = selector
    ? [{ package: opts.pkg, version: opts.version, scope: { type: "global" }, selector }]
    : (opts.scopes.length ? opts.scopes : [{ type: "global" as const }]).map((scope) => ({
        package: opts.pkg,
        version: opts.version,
        scope,
      }));
  return {
    entries: pins.map(formatProposedPin),
    pins,
    forceCommand: `supplywarden fix ${opts.pkg} --apply --force`,
  };
}

export function formatTriageProposal(proposal: TriageOverrideProposal): string {
  const shown = proposal.entries.join(", ");
  return `Proposal: ${shown}. Pass --apply --force to write it anyway.`;
}

async function withPeerCompanions(
  decision: Decision,
  directs: Array<{ name: string; version: string }>,
  lookup: UpgradeLookup,
): Promise<Decision> {
  if (!lookup.peerDependencies) return decision;
  const targets = [...(decision.upgradeTargets ?? [])];
  const have = new Set(targets.map((target) => target.name));
  const additions: NonNullable<Decision["upgradeTargets"]> = [];
  for (const target of targets) {
    if (!target.to) continue;
    const publishedPeers = (await lookup.peerDependencies(target.name, target.to)) ?? {};
    for (const dep of directs) {
      if (have.has(dep.name) || !dep.version || dep.version === "?" || dep.name === target.name) {
        continue;
      }
      const installedPeers = await lookup.peerDependencies(dep.name, dep.version);
      const installedRange = installedPeers?.[target.name];
      const rejectsTarget = Boolean(installedRange && !rangeAccepts(installedRange, target.to));
      const requiredRange = publishedPeers[dep.name];
      const targetRejectsInstalled = Boolean(
        requiredRange && !rangeAccepts(requiredRange, dep.version),
      );
      if (!rejectsTarget && !targetRejectsInstalled) continue;
      const to = await companionVersion(dep.name, target.to, requiredRange, lookup);
      if (!to || to === dep.version) continue;
      additions.push({
        name: dep.name,
        from: dep.version,
        to,
        ...(target.filter ? { filter: target.filter } : {}),
      });
      have.add(dep.name);
    }
  }
  if (!additions.length) return decision;
  return { ...decision, upgradeTargets: [...targets, ...additions] };
}

async function companionVersion(
  name: string,
  preferred: string,
  requiredRange: string | undefined,
  lookup: UpgradeLookup,
): Promise<string | undefined> {
  const atPreferred = await lookup.peerDependencies?.(name, preferred);
  if (atPreferred && (!requiredRange || rangeAccepts(requiredRange, preferred))) return preferred;
  if (requiredRange) return lookup.minMatching?.(name, requiredRange);
  return undefined;
}

function rangeAccepts(range: string, version: string): boolean {
  try {
    return satisfies(version, range, { includePrerelease: true });
  } catch {
    return false;
  }
}

/** Installed parents whose range does not accept `version`. */
export function rejectedBy(dependers: Depender[] | undefined, version: string): Depender[] {
  if (!dependers?.length || !valid(version)) return [];
  const seen = new Set<string>();
  const out: Depender[] = [];
  for (const depender of dependers) {
    const key = `${depender.parent}\0${depender.range}`;
    if (seen.has(key)) continue;
    seen.add(key);
    if (rangeAccepts(depender.range, version)) continue;
    out.push(depender);
  }
  return out.sort((a, b) => a.parent.localeCompare(b.parent));
}

/**
 * One sentence when a naive bump of `pkg` lands outside a parent's range.
 * A proven root upgrade is named as the step that moves that range.
 */
export function rangeRejectionNote(opts: {
  pkg: string;
  version: string;
  dependers?: Depender[];
  strategy: "upgrade" | "override";
  upgradeTargets?: UpgradeTarget[];
}): string | undefined {
  const rejected = rejectedBy(opts.dependers, opts.version);
  if (!rejected.length) return undefined;
  const asking = formatAsking(opts.pkg, rejected);
  const outside = `${asking}. That does not include ${opts.version}.`;
  if (opts.strategy === "upgrade") {
    const moved = (opts.upgradeTargets ?? [])
      .filter((target) => target.to)
      .map((target) =>
        target.from
          ? `${target.name}@${target.from} → ${target.to}`
          : `${target.name}@${target.to}`,
      )
      .join(", ");
    if (!moved) return outside;
    return `${outside} Upgrade the root first. ${moved} moves that range.`;
  }
  const parent = rejected.length === 1 ? "That parent can" : "Those parents can";
  return `${outside} The pin forces ${opts.pkg}@${opts.version}. ${parent} fail to build.`;
}

function formatAsking(pkg: string, rejected: Depender[]): string {
  const byRange = new Map<string, string[]>();
  for (const depender of rejected) {
    const label = depender.version ? `${depender.parent}@${depender.version}` : depender.parent;
    const list = byRange.get(depender.range) ?? [];
    list.push(label);
    byRange.set(depender.range, list);
  }
  return [...byRange.entries()]
    .map(([range, parents]) => {
      const verb = parents.length > 1 ? "ask" : "asks";
      return `${parents.join(" and ")} ${verb} for ${pkg}@${range}`;
    })
    .join("; ");
}

function stripVersion(segment: string): string {
  const at = segment.lastIndexOf("@");
  if (at <= 0) return segment;
  return segment.slice(0, at);
}

/** Version that sits outside every advisory range — not merely the `patchedVersion` field. */
export function firstSafeForcedVersion(advisories: Advisory[]): string | undefined {
  const floors: string[] = [];
  for (const advisory of advisories) {
    if (
      advisory.patchedVersion &&
      valid(advisory.patchedVersion) &&
      !stillVulnerable(advisory.patchedVersion, [advisory])
    ) {
      floors.push(advisory.patchedVersion);
      continue;
    }
    const inferred = inferSafeFloorFromVulnerableRange(advisory.vulnerableRange);
    if (inferred) floors.push(inferred);
  }
  if (!floors.length) return undefined;
  let best = floors[0]!;
  for (const floor of floors.slice(1)) {
    if (gt(floor, best)) best = floor;
  }
  return stillVulnerable(best, advisories) ? undefined : best;
}

export function stillVulnerable(version: string, advisories: Advisory[]): boolean {
  if (!valid(version)) return true;
  return advisories.some((a) => {
    try {
      return satisfies(version, a.vulnerableRange, { includePrerelease: true });
    } catch {
      return false;
    }
  });
}
