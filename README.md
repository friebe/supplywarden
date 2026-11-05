# supplywarden

Getting tired of running the same audit commands over and over — or pasting the audit into an LLM again and again — is how this started.

Dependabot and Renovate are good at proposing root upgrades. For transitive dependencies they often cannot do much and leave you alone: dig through the tree, decide whether to pin, guess if the pin is breaking, figure out which roots still pull the vulnerable copy, and whether it makes sense to upgrade, refresh the lockfile, wait, or accept the risk. The individual steps are usually simple commands. Across three or four packages they multiply, and every time you ask the same questions and do the same research.

supplywarden will not magically fix every vulnerability — that part stays highly custom to your tree. What it does give you is a local proposal for the next step: who pulls the package in, whether a refresh or root upgrade is enough, when an override is safe to write automatically, and when you should decide yourself (with a concrete pin proposal and `--force` if you consciously want it).

A local CLI for one developer. It runs `npm`, `pnpm`, or `yarn` audit (including pnpm workspaces), shows which root pulls a transitive package in, and prints the next command.

```bash
npx supplywarden check
npx supplywarden check --open
npx supplywarden check --strict
npx supplywarden why qs
npx supplywarden fix
npx supplywarden fix marked --apply
npx supplywarden fix uuid --apply --force
npx supplywarden fix --apply
npx supplywarden verify qs
npx supplywarden verify qs --apply
npx supplywarden doctor
npx supplywarden report
```

| Command | What you get |
|---------|----------------|
| `check` | One row per audit finding: installed version, roots, chain, and a command. Overrides already in `package.json` that the audit does not list are marked **drop**. Nothing is written. |
| `check --strict` | Exit `1` when a finding still needs a refresh, upgrade, override, or triage decision. |
| `check --open` | Same as `check`, then open the HTML report. |
| `why <pkg>` | Who pulls that package in. |
| `fix [pkg]` | Dry-run for open findings. A package name limits it to that finding. Nothing is written. |
| `fix <pkg> --apply` | Writes that package's override into `package.json`, or refreshes the lockfile. A root upgrade still only runs when `autoApplyRootUpgrade` is true. |
| `fix <pkg> --apply --force` | Consciously writes a **triage** proposal anyway (version selector or scoped/global pin). Without `--force`, triage never writes. |
| `fix --apply` | Writes every open pin that is not triage. |
| `verify <pkg>` | Removes that override, installs, audits, then puts it back. |
| `verify <pkg> --apply` | Leaves the override out when the audit stays clean. |
| `verify` | Same probe for every override the audit does not list. |
| `doctor` | Package manager and lockfile. |
| `report` | Same picture as `check`, written as HTML. |

Global flags on every command: `--cwd <dir>`, `--html [path]`, `--open`.

A row is one of these actions:

- **refresh** — the patched version already satisfies every immediate parent range. Refresh the lockfile (`npm update` / `pnpm update` / `yarn upgrade`) before changing a root or writing an override.
- **upgrade** — a newer root version closes the advisory. Only roots that still pull a **vulnerable** copy are named. The command is one `npm install`, `pnpm add`, or `yarn add` for that root and every direct dependency whose peer range would reject the new version. In a pnpm workspace the command is `pnpm --filter <name> add` for the member that still depends on it. A `catalog:` dependency is a line in `pnpm-workspace.yaml`, not `pnpm add`. `nx` uses `npx nx migrate nx@<version>`. `@angular/*` uses one `npx ng update` for the whole set. `storybook` and `@storybook/*` use one `npx storybook@<version> upgrade`. When several packages must move together, Do lists every command. When an installed parent range rejects the safe version, the summary names that parent and says to upgrade the root first.
- **override** — pin the patched version under each package that still depends on it (`"body-parser": { "qs": "6.11.2" }`), or globally when the vulnerable copy is a direct dependency. Automatic only when the pin stays within the installed major **and** the number of affected parents is at or under `upgradeRootThreshold`. A same-major pin past an exact parent range still applies — that is what overrides are for. `fix <pkg> --apply` writes that pin.
- **triage** — a human decision is required: major-version pin, too many parents for an automatic override, or (when `pinDevelopment` is `false`) a non-critical development/optional tree. No pin is written automatically. The row includes a concrete **proposal** (for a major jump, a version selector such as `"minimatch@>=7 <11.0.1": "11.0.1"` that leaves older major lines untouched) and the command `fix <pkg> --apply --force` to write it deliberately.
- **keep** — the audit is silent and the pin is installed. That silence is the override doing its job. `verify <pkg>` is the probe if you want to test removing it.
- **drop** — the override is unused: the package is not in the lockfile, or `package.json` already depends on that same version.

`check` does not write a ledger. The only project file `fix --apply` and `verify --apply` change is `package.json` (and the lockfile, when an install runs). See `decision-layer.md` for the full decision flowchart.

## Config

`.supplywardenrc.json` in the project. Example: `.supplywardenrc.example.json`.

| Key | Default | Effect |
|-----|---------|--------|
| `audit.minSeverity` | `"high"` | Drop audit findings below this label. |
| `upgradeRootThreshold` | `3` | This many vulnerable roots or fewer: prefer a root upgrade. More: no automatic multi-root upgrade. The same number gates automatic overrides: more affected parents than this go to triage instead of a silent pin. |
| `pinDevelopment` | `true` | Pin a development or optional dependency when a root upgrade cannot close it. `false` leaves that row as triage, unless the advisory is critical. |
| `autoApplyRootUpgrade` | `false` | When `true`, `fix --apply` runs the suggested root upgrade. |
| `htmlTemplate` | `"default"` | `"default"`, `"compact"`, or a path to your own HTML file. A custom file must contain `<!--SUPPLYWARDEN_DATA-->`. |

An upgrade is named only when a published root version is proven to move the vulnerable package out of the advisory. Skipped next patches are named.

## Development

Node 20 or newer runs the published CLI. Local Vite+ (`vp`) needs Node `^22.18.0`, `^24.11.0`, or `>=26`.

```bash
pnpm install
pnpm test
pnpm run check
pnpm run build
pnpm try -- check --cwd fixtures/npm-simple
```
