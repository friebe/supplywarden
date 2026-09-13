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

Config: `.supplywardenrc.json` (see `.supplywardenrc.example.json`). Kitchen-sink demo: `fixtures/npm-mixed`.
