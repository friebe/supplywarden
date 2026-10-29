export type Severity = "critical" | "high" | "medium" | "low" | "unknown";

export type Strategy = "override" | "upgrade" | "wait";

export type Action = "upgrade" | "override" | "wait" | "keep" | "drop";

export type ValidationCode =
  | "VERSION_NOT_FOUND"
  | "NOT_IN_TREE"
  | "STILL_VULNERABLE"
  | "NOOP_OVERRIDE"
  | "INVALID_SCOPE"
  | "INTRODUCES_VULN"
  | "DEPRECATED_VERSION"
  | "PEER_CONFLICT"
  | "CONFLICTING_OVERRIDES"
  | "VERIFY_FAILED"
  | "OK";

export type PackageManager = "npm" | "pnpm" | "yarn";

export type Advisory = {
  ghsaId?: string;
  cveId?: string;
  severity: Severity;
  vulnerableRange: string;
  patchedVersion?: string;
};

export type OverrideScope = { type: "global" } | { type: "scoped"; parent: string };

export type AuditConfig = {
  /** Ignore audit findings below this severity. */
  minSeverity: Severity;
};

export type SupplywardenConfig = {
  upgradeRootThreshold: number;
  /** When true, `fix --apply` runs the suggested root upgrade (`npm install` / `pnpm add` / `nx migrate`). Default: suggest only. */
  autoApplyRootUpgrade: boolean;
  /** Built-in `default` / `compact`, or an HTML file relative to the project root. */
  htmlTemplate: string;
  audit: AuditConfig;
};

export type RootPackage = {
  name: string;
  version: string;
  range?: string;
};

export type DependencyKind = "production" | "development" | "optional";

export type DependencyChain = {
  path: string[];
  package: string;
  version: string;
};

/** An installed package whose dependency range names this package. */
export type Depender = {
  parent: string;
  range: string;
  version?: string;
};

export type GraphAnalysis = {
  package: string;
  versions: string[];
  inTree: boolean;
  roots: RootPackage[];
  chains: DependencyChain[];
  /** Parent lockfile specs for this package (what dependents asked for, not installed). */
  dependerRanges: string[];
  /** Who asked for those specs. Omitted by callers that only need the ranges. */
  dependers?: Depender[];
  /** Direct dependencies of the project, with the version the lockfile installed. */
  directs?: Array<{ name: string; version: string }>;
  /** Where this package sits in the install tree. Omitted if not in the lockfile. */
  dependencyKind?: DependencyKind;
};

export type PackageAlertGroup = {
  package: string;
  manifestPath: string;
  installedVersion?: string;
  advisories: Advisory[];
  maxSeverity: Severity;
  forcedVersion?: string;
  mergedVulnerableRange: string;
};

export type UpgradeTarget = {
  name: string;
  from?: string;
  to?: string;
  /** Newer versions tried before `to` that still allow the vuln (e.g. 23.2.1). */
  skipped?: string[];
};

export type Decision = {
  strategy: Strategy;
  reason: string;
  forcedVersion?: string;
  scope: OverrideScope;
  /** Every override to write. One scoped entry per parent, or a single global pin. */
  scopes?: OverrideScope[];
  upgradeTargets?: UpgradeTarget[];
};

export type ValidationIssue = {
  code: ValidationCode;
  message: string;
  hint?: string;
  blocking: boolean;
};

/** One transitive finding or leftover override, computed for this run. Nothing is stored. */
export type Finding = {
  package: string;
  severity: Severity;
  advisories: Advisory[];
  installed: string[];
  roots: string[];
  chains: string[];
  dependencyKind?: DependencyKind;
  action: Action;
  summary: string;
  commands: string[];
  forcedVersion?: string;
  upgradeTargets?: UpgradeTarget[];
  outcome?: "keep" | "removable" | "failed";
};

export type ReportModel = {
  title: string;
  generatedAt: string;
  cwd: string;
  summary: Record<string, number | string>;
  entries: Finding[];
  groups?: PackageAlertGroup[];
  decision?: Decision;
  validation?: ValidationIssue[];
};

export type CommandResult = {
  exitCode: number;
  report: ReportModel;
  messages: string[];
  writtenFiles?: string[];
};

export type RegistryClient = {
  verifyPackageVersion: (
    pkg: string,
    version: string,
  ) => Promise<{ exists: boolean; deprecated?: string | null }>;
  /** Latest published version, or undefined if lookup failed. */
  latestVersion?: (pkg: string) => Promise<string | undefined>;
  getLatestMatching?: (pkg: string, range: string) => Promise<string | undefined>;
  /** Published versions newer than `from`, ascending, excluding deprecated. `undefined` if lookup failed. */
  versionsNewerThan?: (pkg: string, from: string) => Promise<string[] | undefined>;
  /** Declared range for `dep` in `pkg@version` (dependencies / optionalDependencies). */
  dependencyRange?: (pkg: string, version: string, dep: string) => Promise<string | undefined>;
  /** Lowest published version that satisfies `range`. */
  minMatching?: (pkg: string, range: string) => Promise<string | undefined>;
  /** Peer ranges declared by `pkg@version`. `undefined` when that version was not found. */
  peerDependencies?: (pkg: string, version: string) => Promise<Record<string, string> | undefined>;
  advisoriesFor?: (pkg: string, version: string) => Promise<Advisory[]>;
};

export type AuditFinding = {
  package: string;
  severity: Severity;
  range?: string;
  ghsaId?: string;
  cveId?: string;
  patchedVersion?: string;
  title?: string;
};

export type AuditResult = {
  vulnerabilities: AuditFinding[];
  error?: string;
};

export type AuditClient = {
  audit: (cwd: string) => Promise<AuditResult>;
};

export type InstallClient = {
  install: (cwd: string) => Promise<{ ok: boolean; error?: string }>;
  runCommand?: (
    cwd: string,
    file: string,
    args: string[],
  ) => Promise<{ ok: boolean; error?: string }>;
};
