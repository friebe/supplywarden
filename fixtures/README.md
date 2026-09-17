# Fixtures

Mini projects for testing supplywarden without `npm link` into real repos.

| Fixture | Scenario |
|---------|----------|
| `npm-simple` | express → qs@6.5.0 |
| `npm-five-overrides` | 5 overrides in package.json |
| `npm-removable` | Override, vuln already gone |
| `npm-overdue` | reviewBy expired + HIGH |
| `npm-drift` | metadata without package.json override |
| `npm-scoped-override` | `{ "body-parser": { "qs": "6.11.2" } }` |
| `npm-noop-override` | Lockfile already on patched version |
| `npm-mixed` | Kitchen-sink board. **Without audit:** OVERDUE production (`qs`) + development (`picomatch` via eslint), OK (`ip`), Ok·verified KEEP (`follow-redirects`), weak no-op override (`nth-check`), optional (`fsevents`), REMOVABLE `already-at-patched` (`lodash`), `not-in-tree` (`request`), `no-vulnerable-version` (`debug`), DRIFT (`minimist`), PENDING_VERIFY (`semver`), VERIFY_FAILED (`tar`), UNTRACKED (`ws`). **With `alerts/mixed.json`:** NEW upgrade `smol-toml` (only root `nx@23.2.0` → **23.2.5**, not 23.2.1), NEW mixed upgrade `tslib` (`nx` + `lodash`), NEW override `serialize-javascript` (4 roots > threshold). |
| `alerts/mixed.json` | Dependabot dump for `npm-mixed`. Live `npm audit` will not invent these fake packages — pass the file to `check`: `pnpm try -- check fixtures/alerts/mixed.json --cwd fixtures/npm-mixed --open` |
| `npm-mixed/supplywarden.registry.json` | Packument stubs. Real `nx@23.2.1` already depends on patched `smol-toml@1.6.1`; the stub keeps 23.2.1 on `^1.3.1` and names **23.2.5** as the first safe root. |
