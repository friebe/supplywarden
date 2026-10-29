# Fixtures

Mini projects for tests. One directory is one lockfile, because the CLI reads a single package manager per folder (`pnpm-lock.yaml`, then `yarn.lock`, then `package-lock.json`).

| Fixture | Why it exists |
|---------|----------------|
| `npm-simple` | express → qs@6.5.0, no override. The usual audit finding. |
| `pnpm-simple` | Same tree in a pnpm v9 lockfile. |
| `yarn-simple` | Same tree in a classic Yarn lockfile. |
| `yarn-berry-simple` | Same tree in a Yarn Berry lockfile. |
| `npm-noop-override` | express tree whose lockfile is already on the patched qs. |
| `npm-still-vulnerable` | uuid@9, used when a pin has to leave the advisory range. |
| `npm-mixed` | Overrides that stay, overrides that can go, qs pinned only under express and body-parser, `@demo/core` with peer `@demo/common`, and `old-tool` whose newer release still depends on vulnerable marked. `supplywarden.registry.json` stubs those packuments. |
| `npm-migrations` | Three upgrade families. `@angular/core` + `@angular/common` (forms stays, its peer already allows the new core) move with one `npx ng update`. `nx` uses `npx nx migrate nx@<version>`. `storybook` + `@storybook/react` (addon-essentials stays) use one `npx storybook@<version> upgrade`. The registry stub proves the next version. |
| `audit/` | Saved npm audit JSON for the parser. Not a project. |
