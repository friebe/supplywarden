# supplywarden

Supply-chain governance for npm projects — triage, audited overrides, and compliance checks.

Not a replacement for `npm audit fix`: **supplywarden** triages transitive Dependabot/audit findings, decides upgrade vs. override, and keeps overrides accountable in `security-metadata.json`.

CLI name: **`supplywarden`** (`npx supplywarden …`). Config: `.supplywardenrc.json`.

## Basic flow

Three different jobs — do not mix them up:

| | Command | Question |
|--|---------|----------|
| Environment | `doctor` | Can this repo run overrides? (PATH, lockfile, metadata). No vulnerability scan. |
| New finding | `analyze` / `fix` | Upgrade the root or add an override? Input: Dependabot JSON **or** no file → `npm`/`pnpm`/`yarn audit`. `analyze` is dry-run; `fix --apply` writes. |
| Existing overrides | `check` | Still needed, drifted, overdue, or safe to drop? Reads `security-metadata.json`. CI gate: `--strict`. |

```
once:      doctor → init
new CVE:   why <pkg> → analyze → fix --apply --yes
ongoing:   check --audit --strict
cleanup:   check → verify [--apply]
drift:     sync
```

Develop with **pnpm** (flags after the command; one `--` after `try` is enough):

```bash
corepack enable
pnpm install
pnpm test
pnpm try -- doctor --cwd fixtures/npm-simple
pnpm try -- check --cwd fixtures/npm-mixed --html --open
pnpm try -- analyze --cwd fixtures/npm-mixed
pnpm try -- analyze --cwd fixtures/npm-mixed fixtures/alerts/mixed.json
pnpm try -- why --cwd fixtures/npm-mixed qs
```

```bash
npx supplywarden doctor
npx supplywarden init
npx supplywarden why qs
npx supplywarden analyze
npx supplywarden analyze fixtures/alerts/mixed.json
npx supplywarden fix --apply --yes
npx supplywarden fix --audit --apply --yes
npx supplywarden fix fixtures/alerts/mixed.json --apply --yes
npx supplywarden check --html --open
npx supplywarden check --audit --strict
npx supplywarden verify
npx supplywarden verify --apply
npx supplywarden sync
npx supplywarden report
```

## Commands

| Command | Purpose |
|---------|---------|
| `doctor` | Environment only: npm/pnpm on PATH, lockfile, metadata. No CVE scan |
| `init` | import existing `overrides` into `security-metadata.json` |
| `analyze [file]` | New findings, dry-run (upgrade vs override). No file → `npm`/`pnpm`/`yarn audit`. `--skip-audit` disables that |
| `fix [file] --apply --yes` | Same as `analyze`, then validation gate → metadata + `package.json` |
| `check [--strict] [--apply] [--audit]` | Existing overrides: OVERDUE, DRIFT, REMOVABLE, RESOLVED, PENDING_VERIFY, VERIFY_FAILED, UNTRACKED; optional `NEW` from audit |
| `verify [--apply] [--skip-install]` | Prove a REMOVABLE override: drop → install → audit → restore or apply |
| `sync` | metadata → `package.json` overrides (including `pnpm.overrides`) |
| `why <package>` | who pulls in the package (use before `analyze`/`fix`) |
| `report` | write `supplywarden-report.html` in `--cwd` (same data as `check`, no new scan forced unless audit is on) |

Global flags (every command): `--cwd <dir>`, `--html [path]`, `--open`. `--open` only opens a file if `--html` was also passed (`report` writes HTML even without `--html`). `--skip-audit` on `analyze` / `fix` / `check` skips the package-manager audit.

Demo with every status and known CVEs: `fixtures/npm-mixed` + `fixtures/alerts/mixed.json` (see `fixtures/README.md`). `npm-simple` has neither metadata nor overrides.

## Best flow

Do not run every command on every pass. Typical order:

**1. Once per repo**

```bash
npx supplywarden doctor
npx supplywarden init          # only if package.json already has overrides
```

`doctor` checks the lockfile and toolchain. `init` imports existing overrides into `security-metadata.json` (without advisories — those arrive later via alert/audit).

**2. New vulnerability (Dependabot JSON or audit)**

```bash
npx supplywarden why qs
npx supplywarden analyze                  # no file → npm/pnpm/yarn audit
npx supplywarden analyze fixtures/alerts/mixed.json
npx supplywarden fix --apply --yes        # same: audit if no file
```

`why` shows the root and chain before you write. `analyze` without a file runs the package manager’s audit (`npm audit --json`, `pnpm audit --json`, or `yarn audit --json` / `yarn npm audit --json`). A Dependabot JSON file still works if you pass one. `fix --apply` writes only after the validation gate. `--yes` accepts impact warnings.

**3. Ongoing (PR / CI / weekly)**

```bash
npx supplywarden check --audit --strict --html --open
```

Classifies overrides and finds untracked audit findings (`NEW`). In CI: `--strict`, without `--open`. `report` writes the same dashboard without forcing a new scan.

**4. Clean up overrides — propose first, then prove**

```bash
npx supplywarden check                 # heuristic: safe to remove?
npx supplywarden verify                # probe: drop override → install → audit → restore
npx supplywarden verify --apply        # drop only CONFIRMED_REMOVABLE
```

`check --apply` removes heuristic hits without install. For CRA/review, prefer `verify --apply`.

**5. Only on drift**

```bash
npx supplywarden sync
```

Metadata is the source of truth; `sync` rewrites `package.json` / `pnpm.overrides` when someone changed overrides by hand.

| Situation | Command |
|-----------|---------|
| First setup | `doctor` → optional `init` |
| Alert / new CVE | `why` → `analyze` (audit or JSON) → `fix --apply --yes` |
| Regular gate | `check --audit --strict` |
| “Can this override go?” | `check`, then `verify` / `verify --apply` |
| package.json drifted | `sync` |
| Share the dashboard | `check --html --open` or `report` |

## Audit (without an alert file)

`analyze` and `fix` **without a file** always run the package manager in `--cwd`:

- npm → `npm audit --json`
- pnpm → `pnpm audit --json`
- yarn → `yarn audit --json`, fallback `yarn npm audit --json`

`--skip-audit` turns that off (then you must pass a Dependabot JSON file). `--audit` is optional; it is the default whenever no file is given.

`check` is different: it only runs audit when `audit.enabled` is true in `.supplywardenrc.json` or you pass `--audit`.

```json
{
  "audit": {
    "enabled": true,
    "minSeverity": "high"
  }
}
```

Packages already covered by an override are not reported as `NEW`. Active overrides that audit no longer lists **and** whose lockfile has no vulnerable version left are marked `RESOLVED`. `--strict` fails on overdue high/critical, drift, verify_failed, new findings, or untracked overrides.

## Verify (is the override really removable?)

`check` only proposes REMOVABLE from the lockfile + stored advisories. `verify` checks that destructively, **opt-in**:

1. Snapshot of `package.json`, lockfile, metadata
2. Candidates one by one: drop override → install → audit
3. Advisory still present / tree vulnerable again / install fail → **KEEP** (restore)
4. Otherwise **CONFIRMED_REMOVABLE**
5. Without `--apply`, always restore. With `--apply`, only confirmed drops.

`--skip-install` probes without `npm`/`pnpm install` (tests). Not part of `check --strict` (install is slow and mutates the tree).

## Validation gate

No apply on `STILL_VULNERABLE`, `NOOP_OVERRIDE`, `VERSION_NOT_FOUND`, `INTRODUCES_VULN`. After apply: post-verify, otherwise rollback.

## Config

See `.supplywardenrc.example.json`. Default file in the project: `.supplywardenrc.json`. An existing `.vulnfixrc.json` is still read (`doctor` warns). Override the actor with `SUPPLYWARDEN_USER` (fallback `VULNFIX_USER`).

## Roadmap

Planned, without needing another rename:

- SBOM (CycloneDX / SPDX)
- CRA-oriented checks
- Configurable NIST / policy rules
