# supplywarden

Triage transitive npm audit/Dependabot findings, decide upgrade vs override, and keep overrides accountable in `security-metadata.json`.

```
once:      doctor → init
everyday:  check [--strict]
review:    check --open
write:     fix --apply
cleanup:   verify [--apply]
drift:     sync
```

```bash
npx supplywarden doctor
npx supplywarden init                 # only if package.json already has overrides
npx supplywarden check --strict       # CI
npx supplywarden check --open         # local HTML report
npx supplywarden fix --apply          # no file: audit; or pass a Dependabot JSON
npx supplywarden verify               # probe REMOVABLE (install + audit, then restore)
npx supplywarden verify --apply       # drop only confirmed overrides from package.json
npx supplywarden sync                 # metadata → package.json if someone edited overrides by hand
```

| Command | Job |
|---------|-----|
| `doctor` | PATH, lockfile, metadata. No CVE scan. |
| `init` | Import existing overrides into `security-metadata.json`. |
| `check` | Audit, triage NEW (upgrade vs override), say if overrides are still needed. `--strict` fails CI on overdue/drift/new/untracked. |
| `fix --apply` | Write the upgrade/override from audit or a Dependabot JSON file. |
| `verify [--apply]` | Prove a REMOVABLE override: drop → install → audit. Without `--apply` always restore; with `--apply` remove only confirmed ones. |
| `sync` | Rewrite `package.json` overrides from metadata. |

`check` only reads. The only way to drop an override is `verify --apply`.

## `--strict`

Without `--strict`, `check` always exits 0: it prints the report, CI stays green.

With `--strict` it is a gate (exit 1) if any of these is true:

- **NEW** — untracked audit finding (not yet an override)
- **UNTRACKED** — override in `package.json` but not in `security-metadata.json`
- **OVERDUE** on a high/critical advisory — review date passed
- **DRIFT** — metadata and `package.json` disagree
- **VERIFY_FAILED** — last `verify`/`fix` apply failed
- the package-manager audit itself failed

REMOVABLE/RESOLVED alone do not fail the gate (`verify --apply` is cleanup, not a blocker).

## Config

File: `.supplywardenrc.json` in the project (example: `.supplywardenrc.example.json`). Only these keys do something today:

| Key | Default | Effect |
|-----|---------|--------|
| `audit.minSeverity` | `"high"` | After `npm`/`pnpm`/`yarn audit`, drop findings below this label. `critical` > `high` > `medium` > `low`. |
| `upgradeRootThreshold` | `3` | `check` / `fix`: if this many (or fewer) roots pull the vuln package, prefer **upgrade**; more roots → **override**. |
| `defaultReviewDays` | `7` | New overrides get `reviewBy` = now + N days. After that, `--strict` fails on high/critical **OVERDUE**. |
| `metadataPath` | `"security-metadata.json"` | Where override records live. |
| `impactWarnThreshold` | `20` | `fix --apply` logs a warning if the estimated lockfile change is this large (does not block). |
| `impactBlockThreshold` | `100` | `fix --apply` refuses if the estimated change is this large. |

**`minSeverity: "high"`** is the usual CI setting: the audit still runs in full, but medium/low never become `NEW` and do not fail `--strict`. That cuts noise (prototype-pollution-in-a-dev-tool, etc.) so the gate stays about exploitable prod issues.

Set `"medium"` if you want those in the report too. `"critical"` is stricter (only critical `NEW`). Dependabot JSON files are **not** filtered — only live audit findings.

Kitchen-sink demo: `fixtures/npm-mixed`.
