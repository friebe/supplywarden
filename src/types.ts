export type Severity = "critical" | "high" | "medium" | "low" | "unknown";

export type Strategy = "override" | "upgrade" | "wait" | "defer";

export type EntryStatus =
  | "active"
  | "pending_verify"
  | "verify_failed"
  | "resolved"
  | "superseded";

export type RemovableReason =
  | "not-in-tree"
  | "no-vulnerable-version"
  | "already-at-patched"
  | "root-upgrade-candidate"
  | "audit-clear";

export type VerifyOutcome = "KEEP" | "CONFIRMED_REMOVABLE" | "VERIFY_FAILED";

export type CheckStatus =
  | "OK"
  | "NEW"
  | "UNTRACKED"
  | "REMOVABLE"
  | "RESOLVED"
  | "OVERDUE"
  | "DRIFT"
  | "STALE"
  | "PENDING_VERIFY"
  | "VERIFY_FAILED"
  | "DEFERRED";

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

export type OverrideScope =
  | { type: "global" }
  | { type: "scoped"; parent: string };

export type MetadataEntry = {
  id: string;
  status: EntryStatus;
  package: string;
  forcedVersion: string;
  scope: OverrideScope;
  advisories: Advisory[];
  reason: string;
  strategy: Strategy;
  rootPackages: string[];
  dependencyChains: string[];
  packageManager: PackageManager;
  manifestPath: string;
  createdAt: string;
  createdBy: string;
  reviewBy: string;
  reviewReason: string;
  needsReview?: boolean;
  resolvedAt?: string | null;
  resolvedBy?: string | null;
  resolution?: string | null;
};

export type SecurityMetadata = {
  $schema?: string;
  version: 1;
  entries: MetadataEntry[];
};

export type AuditConfig = {
  /** Ignore audit findings below this severity. */
  minSeverity: Severity;
};

export type DateLocale = "de" | "en";

export type SupplywardenConfig = {
  upgradeRootThreshold: number;
  /** When true, `fix --apply` runs the suggested root upgrade (`npm install` / `pnpm add` / `nx migrate`). Default: suggest only. */
  autoApplyRootUpgrade: boolean;
  defaultReviewDays: number;
  metadataPath: string;
  /** Built-in `default` / `compact`, or an HTML file relative to the project root. */
  htmlTemplate: string;
  audit: AuditConfig;
  /** CLI/HTML date display. Metadata stays ISO. */
  dateLocale: DateLocale;
  timeZone: string;
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

export type GraphAnalysis = {
  package: string;
  versions: string[];
  inTree: boolean;
  roots: RootPackage[];
  chains: DependencyChain[];
  /** Parent lockfile specs for this package (what dependents asked for, not installed). */
  dependerRanges: string[];
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
  /** From Dependabot `dependency.scope` when present. */
  dependencyKind?: DependencyKind;
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
  upgradeTargets?: UpgradeTarget[];
};

export type ValidationIssue = {
  code: ValidationCode;
  message: string;
  hint?: string;
  blocking: boolean;
};

export type CheckEntry = {
  entry: MetadataEntry;
  status: CheckStatus;
  statuses: CheckStatus[];
  suggestedAction: string;
  /** Canonical CLI to copy from the HTML report (derived from status, not prose). */
  commands?: string[];
  /** Copy-paste root upgrade (`npm install pkg@next`, and/or `npx nx migrate` if a root is `nx`). */
  upgradeCommand?: string;
  /** All root-upgrade CLIs when nx and a normal package are mixed (HTML copy buttons). */
  upgradeCommands?: string[];
  issues: ValidationIssue[];
  removableReason?: RemovableReason;
  roots?: string[];
  chains?: string[];
  installedVersions?: string[];
  dependerRanges?: string[];
  /** production | development | optional. Reports show all three in the Scope column. */
  dependencyKind?: DependencyKind;
  /** Override spec still allows vulnerable versions — keeping it is a no-op. */
  weakOverride?: boolean;
  /** Live audit does not list this package. Parent specs are a hint, not a KEEP. */
  auditClear?: boolean;
  /** Last verify KEEP: "verified 17.09.2026, 11:35 jan" for HTML/markdown. */
  verifiedNote?: string;
  verifyOutcome?: VerifyOutcome;
  decision?: Decision;
};

export type ReportModel = {
  title: string;
  generatedAt: string;
  cwd: string;
  summary: Record<string, number | string>;
  entries: CheckEntry[];
  groups?: PackageAlertGroup[];
  decision?: Decision;
  validation?: ValidationIssue[];
  markdown?: string;
  dateLocale?: DateLocale;
  timeZone?: string;
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
  getLatestMatching?: (
    pkg: string,
    range: string,
  ) => Promise<string | undefined>;
  /** Published versions newer than `from`, ascending, excluding deprecated. `undefined` if lookup failed. */
  versionsNewerThan?: (pkg: string, from: string) => Promise<string[] | undefined>;
  /** Declared range for `dep` in `pkg@version` (dependencies / optionalDependencies). */
  dependencyRange?: (pkg: string, version: string, dep: string) => Promise<string | undefined>;
  /** Lowest published version that satisfies `range`. */
  minMatching?: (pkg: string, range: string) => Promise<string | undefined>;
  advisoriesFor?: (
    pkg: string,
    version: string,
  ) => Promise<Advisory[]>;
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
  runCommand?: (cwd: string, file: string, args: string[]) => Promise<{ ok: boolean; error?: string }>;
};
