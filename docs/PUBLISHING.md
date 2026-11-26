# Publishing

Releases use [Changesets](https://github.com/changesets/changesets) and npm trusted publishing (OIDC) through `vp pm publish` (pnpm), with no npm CLI and no publish script, from [release.yml](../.github/workflows/release.yml); there is no `NPM_TOKEN`.

1. Commit a changeset with your change ([CONTRIBUTING.md → Changesets](CONTRIBUTING.md#changesets)).
2. On `trunk`, the workflow opens or updates the `chore: version packages` PR, which bumps versions and writes each `CHANGELOG.md`.
3. Merging that PR, then approving the `release` environment, runs `vp run release` (a task in the root `vite.config.ts`): it builds every package, then `vp pm publish -r --access public --no-git-checks -- --ignore-scripts` publishes every package whose version isn't on npm, in dependency order (pnpm rewrites `catalog:` and `workspace:` specifiers), and `changeset git-tag` tags each new version; the action pushes the tags and creates the GitHub releases. `release` depends only on the build, because it runs with `id-token: write`; `check:dist`, which installs from the registry, stays in CI.

## One-time setup

1. **Settings → Actions → General**: allow GitHub Actions to create pull requests.
2. **Settings → Environments**: create `release` with yourself as required reviewer, limited to `trunk`.
3. On npm, give each package a trusted publisher: GitHub Actions, `thomasfosterau/effect-auth`, `release.yml`, environment `release`. All seven packages are on npm with one. A new package needs a placeholder published once by hand, so its npm settings exist, before its trusted publisher can be added.
4. Protect `trunk`: pull requests and passing CI required.

`vp pm publish -r` stops at the first failure, before `changeset git-tag` runs. If a name isn't set up, fix it and re-run the failed job; already-published versions are skipped.

To publish by hand (a recovery, with npm credentials): `vp run release:dry-run` to see what would be published, then `vp run release`, then `git push origin --tags`.
