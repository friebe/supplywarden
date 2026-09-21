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
npx supplywarden check alerts.json --open  # NEW from Dependabot JSON (no live audit)
npx supplywarden fix --apply          # NEW: override; root upgrade only if autoApplyRootUpgrade
npx supplywarden verify qs            # drop qs override, install, audit, restore
npx supplywarden verify qs --apply    # same, and keep the drop if the vuln is gone
npx supplywarden verify --apply       # all REMOVABLE leftovers
npx supplywarden sync                 # metadata → package.json if someone edited overrides by hand
```

| Command | Job |
|---------|-----|
| `doctor` | PATH, lockfile, metadata. No CVE scan. |
| `init` | Import existing overrides into `security-metadata.json`. |
| `check` | Audit, triage NEW (upgrade vs override), say if overrides are still needed. `--strict` fails CI on overdue/drift/new/untracked. Optional Dependabot JSON instead of live audit. |
| `fix --apply` | Write **new** findings: override into `package.json` + metadata. Root upgrades are **suggested** as `npm install` / `pnpm add` / `yarn add` to the next version (`npx nx migrate` only if the root is `nx`). They run from this command only if `autoApplyRootUpgrade` is true. No file → audit; or pass a Dependabot JSON. Does **not** drop REMOVABLE. |
| `verify [pkg] [--apply]` | Temporarily drop an override, `install` + `audit`, see if the vuln comes back. No pkg → all **REMOVABLE** leftovers. With a pkg → that override even if `check` still lists it as needed. Without `--apply` always restore; with `--apply` keep the drop only if confirmed. A **KEEP** uses the same upgrade-vs-override triage as `check` (`upgradeRootThreshold`, proven `to`). Root upgrade is a suggestion unless `autoApplyRootUpgrade` is true. |
| `sync` | Rewrite `package.json` overrides from metadata. |

`check` only reads. After `check`, pick the write command from the status — not from habit:

| `check` shows | Next command | What it does |
|---------------|--------------|--------------|
| **NEW** | copy the suggested `npm install` / `pnpm add` (or `npx nx migrate` if the root is `nx`), or `fix --apply` | Override is written by `fix --apply`. Root upgrade is a suggestion unless `autoApplyRootUpgrade` is true. |
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

1. **New** — audit found it, no override yet. Meeting decision: run the suggested root upgrade (`npm install pkg@next` / `pnpm add` / `yarn add`; `npx nx migrate` only when the root is `nx`) or pin an override (`fix --apply`). `fix --apply` only starts the upgrade itself when `autoApplyRootUpgrade` is true.
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
| **New** | First sighting | Copy the suggested upgrade command, or `fix --apply` for an override |
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
| `upgradeRootThreshold` | `3` | `check` / `fix` / `verify`: if this many (or fewer) roots pull the vuln package, prefer **upgrade**; more roots → **override**. Upgrade names a **newer** root version only when that version’s published dependency tree is **proven** to put the vuln package outside the advisory (`express@4.18.2 → 4.21.x` if express then requires safe `qs`; **not** `nx@23.2.0 → 23.2.1` if 23.2.1 still allows vulnerable `smol-toml`). The HTML report names that version next to the finding (`nx@23.2.1 → 23.2.5`). If none prove it, fall back to override. Default: only **suggest** `npm install` / `pnpm add` / `yarn add` of that version. If a finding has both `nx` and a normal package as roots, both commands are listed and run in this session (`npm install lodash@…` then `npx nx migrate`). `verify` runs the same triage on **KEEP** (drop still brings the vuln back). If the root is already latest, fall back to override. Parent specs that still name older versions are a **hint** — `verify <pkg>` tests the drop; live audit decides. |
| `autoApplyRootUpgrade` | `false` | When `true`, `fix --apply` and `verify --apply` run that suggested command. Leave `false` so the board only tells Jan what to run. |
| `defaultReviewDays` | `7` | `init`, `fix --apply`, and a verify **KEEP** (still needed) set `reviewBy` = now + N days. After that, `--strict` fails on high/critical **OVERDUE**. |
| `dateLocale` | `"de"` | CLI and HTML dates: `"de"` (`16.09.2026, 20:12`) or `"en"` (`Sep 16, 2026, 8:12 PM`). `security-metadata.json` stays ISO. |
| `timeZone` | `"Europe/Berlin"` | Timezone for those displayed dates. |
| `metadataPath` | `"security-metadata.json"` | Where override records live. |
| `impactWarnThreshold` | `20` | `fix --apply` logs a warning if the estimated lockfile change is this large (does not block). |
| `impactBlockThreshold` | `100` | `fix --apply` refuses if the estimated change is this large. |

**`minSeverity: "high"`** is the usual CI setting: the audit still runs in full, but medium/low never become `NEW` and do not fail `--strict`. That cuts noise (prototype-pollution-in-a-dev-tool, etc.) so the gate stays about exploitable prod issues.

Set `"medium"` if you want those in the report too. `"critical"` is stricter (only critical `NEW`). Dependabot JSON files are **not** filtered — only live audit findings.

Kitchen-sink demo: `fixtures/npm-mixed` (`check fixtures/alerts/mixed.json --cwd fixtures/npm-mixed`). `supplywarden.registry.json` in that folder stubs packuments so the board can show `nx@23.2.0 → 23.2.5` instead of live npm’s next patch.
