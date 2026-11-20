# Publishing

Releases use [Changesets](https://github.com/changesets/changesets) and npm trusted publishing (OIDC) through `pnpm publish`, with no npm CLI, from [release.yml](../.github/workflows/release.yml); there is no `NPM_TOKEN`.

1. Commit a changeset with your change ([CONTRIBUTING.md → Changesets](CONTRIBUTING.md#changesets)).
2. On `trunk`, the workflow opens or updates the `chore: version packages` PR, which bumps versions and writes each `CHANGELOG.md`.
3. Merging that PR, then approving the `release` environment, publishes every package whose version isn't on npm (`pnpm publish`, which rewrites `catalog:` and `workspace:` specifiers) and tags the release.

## One-time setup

1. **Settings → Actions → General**: allow GitHub Actions to create pull requests.
2. **Settings → Environments**: create `release` with yourself as required reviewer, limited to `trunk`.
3. Publish a placeholder of each of the seven packages once, so its npm settings exist, then add a trusted publisher for each: GitHub Actions, `thomasfosterau/effect-auth`, `release.yml`, environment `release`.
4. Protect `trunk`: pull requests and passing CI required.

`pnpm -r publish` stops at the first failure, before `changeset tag` runs. If a name isn't set up, fix it and re-run the failed job; already-published versions are skipped.
