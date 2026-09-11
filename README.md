# supplywarden

Supply-chain governance for npm projects — triage, audited overrides, and compliance checks.

Not a replacement for `npm audit fix`: **supplywarden** triages transitive Dependabot/audit findings, decides upgrade vs. override, and keeps overrides accountable in `security-metadata.json`.

Develop with **pnpm** (flags after the command; one `--` after `try` is enough):

```bash
corepack enable
pnpm install
pnpm test
pnpm try -- doctor --cwd fixtures/npm-simple
pnpm try -- check --cwd fixtures/npm-mixed --html --open
pnpm try -- analyze --cwd fixtures/npm-mixed fixtures/alerts/mixed.json
```

```bash
npx supplywarden doctor
npx supplywarden init
npx supplywarden check --html --open
npx supplywarden check --audit --strict
npx supplywarden verify
npx supplywarden verify --apply
npx supplywarden analyze
npx supplywarden analyze alert.json
npx supplywarden fix --audit --apply --yes
npx supplywarden fix alert.json --apply --yes
```

## Commands

| Command | Purpose |
|---------|---------|
| `doctor` | pnpm/npm, lockfile, metadata |
| `init` | import existing `overrides` |
| `analyze [alert.json]` | recommendation, no write. Without a file: `npm audit` when `audit.enabled` or `--audit` |
| `fix [alert.json] --apply` | pre-gate → metadata + package.json |
| `check [--strict] [--apply] [--audit]` | OVERDUE / REMOVABLE / DRIFT / new audit findings |
| `verify [--apply]` | probe-remove REMOVABLE, install + audit, restore or apply |
| `sync` | metadata → `package.json` overrides (including `pnpm.overrides`) |
| `why <pkg>` | who pulls in the package |
| `report` | HTML dashboard |

`--html [path]` and `--open` work on every command. `--cwd` points at a project directory.

Demo with every status and known CVEs: `fixtures/npm-mixed` (see `fixtures/README.md`). `npm-simple` has neither metadata nor overrides.

## Best flow

Do not run every command on every pass. Typical order:

**1. Once per repo**

```bash
npx supplywarden doctor
npx supplywarden init          # only if package.json already has overrides
```

`doctor` checks the lockfile and toolchain. `init` imports existing overrides into `security-metadata.json` (without advisories — those arrive later via alert/audit).

**2. New vulnerability (Dependabot alert or audit)**

```bash
npx supplywarden why qs
npx supplywarden analyze alert.json          # or: analyze --audit
npx supplywarden fix alert.json --apply --yes
```

`why` shows the root and chain before you write. `analyze` is a dry-run (upgrade vs. override). `fix --apply` writes only after the validation gate.

**3. Ongoing (PR / CI / weekly)**

```bash
npx supplywarden check --audit --strict --html --open
```

Classifies overrides (OVERDUE, DRIFT, REMOVABLE, RESOLVED) and finds untracked audit findings (`NEW`). In CI: `--strict`, without `--open`. `report` is the same dashboard without forcing a new scan.

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
| Alert / new CVE | `why` → `analyze` → `fix --apply` |
| Regular gate | `check --audit --strict` |
| “Can this override go?” | `check`, then `verify` / `verify --apply` |
| package.json drifted | `sync` |
| Share the dashboard | `check --html` or `report` |

## Audit (without an alert file)

Dependabot JSON remains the default. Optionally, `check` / `analyze` / `fix` discover vulnerabilities via the package manager:

```json
{
  "audit": {
    "enabled": true,
    "minSeverity": "high"
  }
}
```

Then `npm audit --json` (or `pnpm audit` / `yarn npm audit`) runs in `--cwd`. Packages already covered by an override are not reported as `NEW`. Active overrides that audit no longer lists **and** whose lockfile has no vulnerable version left are marked `RESOLVED`. `--audit` forces the run, `--skip-audit` suppresses it. `--strict` fails on new findings.

## Verify (is the override really removable?)

`check` only proposes REMOVABLE from the lockfile + stored advisories. `verify` checks that destructively, **opt-in**:

1. Snapshot of `package.json`, lockfile, metadata
2. Candidates one by one: drop override → install → audit
3. Advisory still present / tree vulnerable again / install fail → **KEEP** (restore)
4. Otherwise **CONFIRMED_REMOVABLE**
5. Without `--apply`, always restore. With `--apply`, only confirmed drops.

Not part of `check --strict` (install is slow and mutates the tree).

## Validation gate

No apply on `STILL_VULNERABLE`, `NOOP_OVERRIDE`, `VERSION_NOT_FOUND`, `INTRODUCES_VULN`. After apply: post-verify, otherwise rollback.

## Config

See `.supplywardenrc.example.json`. Default file in the project: `.supplywardenrc.json`. An existing `.vulnfixrc.json` is still read (`doctor` warns).

## Roadmap

Planned, without needing another rename:

- SBOM (CycloneDX / SPDX)
- CRA-oriented checks
- Configurable NIST / policy rules
