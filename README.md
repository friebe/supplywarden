# supplywarden

Triage transitive npm audit/Dependabot findings, decide upgrade vs override, and keep overrides accountable in `security-metadata.json`.

```
once:      doctor → init
everyday:  check [--strict]
review:    check --open
write:     fix --apply
cleanup:   verify [pkg] [--apply]
drift:     sync
```

```bash
npx supplywarden doctor
npx supplywarden init                 # only if package.json already has overrides
npx supplywarden check --strict       # CI
npx supplywarden check --open         # local HTML report
npx supplywarden fix --apply          # NEW only: write upgrade/override
npx supplywarden verify qs            # drop qs override, install, audit, restore
npx supplywarden verify qs --apply    # same, and keep the drop if the vuln is gone
npx supplywarden verify --apply       # all REMOVABLE leftovers
npx supplywarden sync                 # metadata → package.json if someone edited overrides by hand
```

| Command | Job |
|---------|-----|
| `doctor` | PATH, lockfile, metadata. No CVE scan. |
| `init` | Import existing overrides into `security-metadata.json`. |
| `check` | Audit, triage NEW (upgrade vs override), say if overrides are still needed. `--strict` fails CI on overdue/drift/new/untracked. |
| `fix --apply` | Write **new** findings: override or root-upgrade into `package.json` + metadata. No file → audit; or pass a Dependabot JSON. Does **not** drop REMOVABLE. |
| `verify [pkg] [--apply]` | Temporarily drop an override, `install` + `audit`, see if the vuln comes back. No pkg → all **REMOVABLE** leftovers. With a pkg → that override even if `check` still lists it as needed. Without `--apply` always restore; with `--apply` keep the drop only if confirmed. |
| `sync` | Rewrite `package.json` overrides from metadata. |

`check` only reads. After `check`, pick the write command from the status — not from habit:

| `check` shows | Next command | What it does |
|---------------|--------------|--------------|
| **NEW** | `fix --apply` | Writes the recommended upgrade or override. |
| **REMOVABLE** / leftover | `verify <pkg> --apply` | Removes that override from `package.json` (after probe). |
| **PENDING_VERIFY** | `npm install` then `check` | Override is already in `package.json`; lockfile has not picked it up yet. Not `verify` — that would drop it. |
| **VERIFY_FAILED** | `why <pkg>` | Last `verify`/`fix --apply` install/audit did not stick. Status + date are in `security-metadata.json`. |
| OVERDUE / DRIFT / UNTRACKED | `why` / `sync` / `init` | Not `fix`. |
| OK, audit clean, parents still declare older specs | `verify <pkg>` | Hint only — live audit after drop decides. Not a forced KEEP. |
| nothing to write | — | `fix --apply` will say there are no new findings (and point you at `verify --apply` if something is REMOVABLE). |

`fix --apply` is not the everyday button. Everyday is `check`. Use `fix` only when you want those NEW rows in the tree. Use `verify <pkg>` to test dropping one override; `verify --apply` without a package name only touches leftovers `check` already marked REMOVABLE.

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
| `upgradeRootThreshold` | `3` | `check` / `fix`: if this many (or fewer) roots pull the vuln package, prefer **upgrade**; more roots → **override**. Upgrade names a **newer** root version than the one installed (`nx@23.3.0 → 23.4.x`). If the root is already latest, fall back to override. Parent specs that still name older versions are a **hint** — `verify <pkg>` tests the drop; live audit decides. |
| `defaultReviewDays` | `7` | New overrides get `reviewBy` = now + N days. After that, `--strict` fails on high/critical **OVERDUE**. |
| `metadataPath` | `"security-metadata.json"` | Where override records live. |
| `impactWarnThreshold` | `20` | `fix --apply` logs a warning if the estimated lockfile change is this large (does not block). |
| `impactBlockThreshold` | `100` | `fix --apply` refuses if the estimated change is this large. |

**`minSeverity: "high"`** is the usual CI setting: the audit still runs in full, but medium/low never become `NEW` and do not fail `--strict`. That cuts noise (prototype-pollution-in-a-dev-tool, etc.) so the gate stays about exploitable prod issues.

Set `"medium"` if you want those in the report too. `"critical"` is stricter (only critical `NEW`). Dependabot JSON files are **not** filtered — only live audit findings.

Kitchen-sink demo: `fixtures/npm-mixed`.
