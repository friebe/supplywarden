# supplywarden

A local CLI for one developer. It runs `npm`, `pnpm`, or `yarn` audit, shows which root pulls a transitive package in, and prints the next command.

```bash
npx supplywarden check
npx supplywarden check --open
npx supplywarden check --strict
npx supplywarden why qs
npx supplywarden fix
npx supplywarden fix marked --apply
npx supplywarden fix --apply
npx supplywarden verify qs
npx supplywarden verify qs --apply
```

| Command | What you get |
|---------|----------------|
| `check` | One row per audit finding: installed version, roots, chain, and a command. Overrides already in `package.json` that the audit does not list are marked **drop**. Nothing is written. |
| `why <pkg>` | Who pulls that package in. |
| `fix [pkg]` | Dry-run for open findings. A package name limits it to that finding. Nothing is written. |
| `fix <pkg> --apply` | Writes that package's override into `package.json`. A root upgrade still only runs when `autoApplyRootUpgrade` is true. |
| `fix --apply` | Writes every open pin. A root upgrade still only runs when `autoApplyRootUpgrade` is true. |
| `verify <pkg>` | Removes that override, installs, audits, then puts it back. |
| `verify <pkg> --apply` | Leaves the override out when the audit stays clean. |
| `verify` | Same probe for every override the audit does not list. |
| `doctor` | Package manager and lockfile. |

A row is one of four actions:

- **upgrade** — a newer root version closes the advisory. The command is one `npm install`, `pnpm add`, or `yarn add` for that root and every direct dependency whose peer range would reject the new version. `nx` uses `npx nx migrate nx@<version>`. `@angular/*` uses one `npx ng update` for the whole set. `storybook` and `@storybook/*` use one `npx storybook@<version> upgrade`. The summary says to update that set together, not one package at a time. When an installed parent range rejects the safe version, the summary names that parent and says to upgrade the root first.
- **override** — pin the patched version under each package that still depends on it (`"body-parser": { "qs": "6.11.2" }`). A direct dependency is pinned globally. `fix <pkg> --apply` writes that one pin. A pin onto a new major is still written, with a warning. A breaking major upgrade of a root does not write an override. When an installed parent range rejects the pinned version, the summary names that parent and says the build can fail.
- **wait** — only when `pinDevelopment` is `false`: a development or optional dependency, not critical, that a root upgrade cannot close. No pin. Critical never waits.
- **keep** — the audit is silent and the pin is installed. That silence is the override doing its job. `verify <pkg>` is the probe if you want to test removing it.
- **drop** — the override is unused: the package is not in the lockfile, or `package.json` already depends on that same version.

`check` does not write a ledger. The only project file `fix --apply` and `verify --apply` change is `package.json` (and the lockfile, when an install runs).

## Config

`.supplywardenrc.json` in the project. Example: `.supplywardenrc.example.json`.

| Key | Default | Effect |
|-----|---------|--------|
| `audit.minSeverity` | `"high"` | Drop audit findings below this label. |
| `upgradeRootThreshold` | `3` | This many roots or fewer: prefer a root upgrade. More: pin. |
| `pinDevelopment` | `true` | Pin a development or optional dependency when a root upgrade cannot close it. `false` leaves that row as wait, unless the advisory is critical. |
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
