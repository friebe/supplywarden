export type Severity = "critical" | "high" | "medium" | "low" | "unknown";

export type Strategy = "override" | "upgrade" | "wait";

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
  | "VERIFY_FAILED";

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
  | "IMPACT_BLOCKED"
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

export type SupplywardenConfig = {
  upgradeRootThreshold: number;
  defaultReviewDays: number;
  metadataPath: string;
  impactWarnThreshold: number;
  impactBlockThreshold: number;
  audit: AuditConfig;
};

export type RootPackage = {
  name: string;
  version: string;
  range?: string;
};

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

export type Decision = {
  strategy: Strategy;
  reason: string;
  forcedVersion?: string;
  scope: OverrideScope;
  upgradeTargets?: Array<{ name: string; from?: string; to?: string }>;
};

export type ValidationIssue = {
  code: ValidationCode;
  message: string;
  hint?: string;
  blocking: boolean;
};

export type ImpactDiff = {
  changedPackages: number;
  warning: boolean;
  blocked: boolean;
};

export type CheckEntry = {
  entry: MetadataEntry;
  status: CheckStatus;
  statuses: CheckStatus[];
  suggestedAction: string;
  /** Canonical CLI to copy from the HTML report (derived from status, not prose). */
  commands?: string[];
  issues: ValidationIssue[];
  removableReason?: RemovableReason;
  roots?: string[];
  chains?: string[];
  installedVersions?: string[];
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
  impact?: ImpactDiff;
  markdown?: string;
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
  getLatestMatching?: (
    pkg: string,
    range: string,
  ) => Promise<string | undefined>;
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
};
