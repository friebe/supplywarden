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
npx supplywarden fix --apply          # NEW: override, or start nx migrate / pm upgrade
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
| `fix --apply` | Write **new** findings: override into `package.json` + metadata, or start a **root upgrade** (`npx nx migrate` when the root is Nx — Nx asks which packages to update). No file → audit; or pass a Dependabot JSON. Does **not** drop REMOVABLE. |
| `verify [pkg] [--apply]` | Temporarily drop an override, `install` + `audit`, see if the vuln comes back. No pkg → all **REMOVABLE** leftovers. With a pkg → that override even if `check` still lists it as needed. Without `--apply` always restore; with `--apply` keep the drop only if confirmed. |
| `sync` | Rewrite `package.json` overrides from metadata. |

`check` only reads. After `check`, pick the write command from the status — not from habit:

| `check` shows | Next command | What it does |
|---------------|--------------|--------------|
| **NEW** | `fix --apply` | Writes an override, or starts the root upgrade (`npx nx migrate` for Nx). |
| **REMOVABLE** / leftover | `verify <pkg> --apply` | Removes that override from `package.json` (after probe). |
| **PENDING_VERIFY** | `npm install` then `check` | Override is already in `package.json`; lockfile has not picked it up yet. Not `verify` — that would drop it. |
| **VERIFY_FAILED** | `verify <pkg>` | Last `verify`/`fix --apply` install/audit did not stick. Retry the probe. Status + date are in `security-metadata.json`. |
| OVERDUE / DRIFT / UNTRACKED | `why` / `sync` / `init` | Not `fix`. |
| OK, audit clean, parents still declare older specs | `verify <pkg>` | Hint only — live audit after drop decides. Not a forced KEEP. |
| **KEEP** after `verify` | — | Override still needed. Metadata records who/when (`resolvedBy` / `resolvedAt`); HTML shows **Ok · verified …**. Next review deadline is now + `defaultReviewDays`. |
| nothing to write | — | `fix --apply` will say there are no new findings (and point you at `verify --apply` if something is REMOVABLE). |

`fix --apply` is not the everyday button. Everyday is `check`. Use `fix` only when you want those NEW rows in the tree. Use `verify <pkg>` to test dropping one override; `verify --apply` without a package name only touches leftovers `check` already marked REMOVABLE.

## Biweekly triage (Jan)

Jan opens the HTML board every two weeks (`check --open`). Set `defaultReviewDays` to `14` so **Overdue** lines up with that meeting, not with the default 7 days.

The board is four piles. Work **Decide** top to bottom, then **Cleanup**. **Tracked** is the ledger of overrides you already accepted.

```
Decide this week  →  new or stuck items (act now)
Waiting           →  override written, lockfile not installed yet
Cleanup           →  safe to drop after verify --apply
Tracked           →  still needed (Ok, including Ok · verified)
```

A package walks the board like this:

1. **New** — audit found it, no override yet. Meeting decision: root upgrade (`fix --apply` → Nx migrate / `npm install`) or pin an override (`fix --apply`).
2. **Pending install** — override is in `package.json`, lockfile is old. Run `npm install` / `pnpm install`, then `check`. Do not `verify` yet (that would drop the new pin).
3. **Ok** — override is in the tree and holding. Next meeting it is still Ok unless the review deadline passed.
4. **Overdue** — `reviewBy` is past. Jan re-opens it: `why <pkg>`, then `verify <pkg>` to see if the pin is still required.
5. After that probe:
   - **Ok · verified 17.09.2026 Jan** — KEEP: vuln came back, pin stays. Date + name are in metadata; `reviewBy` moves two weeks out. Next meeting you see you already looked.
   - **Verify failed** — install broke (peer conflict). Retry `verify <pkg>`. Not the same as KEEP.
   - **Removable** — probe was clean. `verify <pkg> --apply` drops it; it leaves the board.

**Drift** (metadata ≠ `package.json`) and **Untracked** (override in `package.json`, not in metadata) also sit in Decide: `sync` / `init`, not `fix`.

**Development** in the Scope column is a filter, not a pile: the vuln is only on the dev tree. Still decide it; it is not automatically leftover.

| Label on the board | Stage | What Jan does |
|--------------------|-------|----------------|
| **New** | First sighting | `fix --apply` (upgrade or override) |
| **Pending install** | Pin written, lockfile stale | package-manager `install`, then `check` |
| **Ok** | Pin is doing its job | Nothing this week, unless you want to probe |
| **Ok · verified {date} {who}** | Last meeting already probed: still needed | Skip unless the story changed |
| **Overdue** | Review deadline passed | `why`, then `verify` |
| **Verify failed** | Last probe did not even install | `verify <pkg>` again |
| **Removable** / **Resolved** | Probe (or tree) says leftover | `verify <pkg> --apply` |
| **Drift** | Files disagree | `sync` |
| **Untracked** | Override without a metadata row | `init` |

## Do not ship `security-metadata.json`

`security-metadata.json` (and the HTML from `check --open`) is a **team triage board**, not a production artifact. It records package names, GHSA/CVE IDs, forced versions, and dependency chains — a precise map of known weaknesses.

Do not copy it into Docker images, static hosting, public web roots, or any build that outsiders can read. If it is publicly readable, it is an attack source: it tells an adversary exactly where the tree is weak. Keep it in the repo for `check` / CI, and keep HTML reports local.

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
| `upgradeRootThreshold` | `3` | `check` / `fix`: if this many (or fewer) roots pull the vuln package, prefer **upgrade**; more roots → **override**. Upgrade names a **newer** root version than the one installed (`nx@23.3.0 → 23.4.x`). `fix --apply` does **not** rewrite that version in `package.json`. If the root is Nx, it starts `npx nx migrate nx@…` and Nx asks which packages to update. Other roots go through `npm install` / `pnpm add` / `yarn add`. If the root is already latest, fall back to override. Parent specs that still name older versions are a **hint** — `verify <pkg>` tests the drop; live audit decides. |
| `defaultReviewDays` | `7` | `init`, `fix --apply`, and a verify **KEEP** (still needed) set `reviewBy` = now + N days. After that, `--strict` fails on high/critical **OVERDUE**. |
| `dateLocale` | `"de"` | CLI and HTML dates: `"de"` (`16.09.2026, 20:12`) or `"en"` (`Sep 16, 2026, 8:12 PM`). `security-metadata.json` stays ISO. |
| `timeZone` | `"Europe/Berlin"` | Timezone for those displayed dates. |
| `metadataPath` | `"security-metadata.json"` | Where override records live. |
| `impactWarnThreshold` | `20` | `fix --apply` logs a warning if the estimated lockfile change is this large (does not block). |
| `impactBlockThreshold` | `100` | `fix --apply` refuses if the estimated change is this large. |

**`minSeverity: "high"`** is the usual CI setting: the audit still runs in full, but medium/low never become `NEW` and do not fail `--strict`. That cuts noise (prototype-pollution-in-a-dev-tool, etc.) so the gate stays about exploitable prod issues.

Set `"medium"` if you want those in the report too. `"critical"` is stricter (only critical `NEW`). Dependabot JSON files are **not** filtered — only live audit findings.

Kitchen-sink demo: `fixtures/npm-mixed`.
