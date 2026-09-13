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
| `npm-mixed` | Kitchen-sink: OVERDUE (qs), REMOVABLE patched-in-tree (lodash) + relic not-in-tree (`request` override, nothing pulls it), DRIFT, PENDING_VERIFY, VERIFY_FAILED, UNTRACKED still-pulled (ws); known CVEs (qs 6.5.0, semver 7.5.1, minimist 1.2.5, ws 8.5.0) |
