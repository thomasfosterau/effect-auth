# Publishing

Releases use [Changesets](https://github.com/changesets/changesets) and npm trusted publishing (OIDC) through `vp pm publish` (pnpm), with no npm CLI, from [release.yml](../.github/workflows/release.yml); there is no `NPM_TOKEN`.

1. Commit a changeset with your change ([CONTRIBUTING.md → Changesets](CONTRIBUTING.md#changesets)).
2. On `trunk`, the workflow opens or updates the `chore: version packages` PR, which bumps versions and writes each `CHANGELOG.md`.
3. Merging that PR runs three jobs:
   - **Build and pack** (`contents: read`, no `id-token`) installs with `--ignore-scripts`, builds, and runs `vp run release:pack`: [scripts/release.ts](../scripts/release.ts) packs each public package whose version isn't on npm (pnpm rewrites `catalog:` and `workspace:` specifiers) and lists them, in dependency order, in `release/manifest.json`. The tarballs are uploaded as the `release` artifact.
   - **Publish to npm**, after you approve the `release` environment, is the only job with `id-token: write`. It downloads the tarballs and publishes each with `vp pm publish <tarball>`: no install, no build, no dependency cache, nothing from the repository but the files pinning Vite+ and pnpm.
   - **Tag and release** (`contents: write`) runs `node scripts/release.ts tag`, which creates the `<name>@<version>` tag and GitHub release, with that version's CHANGELOG section, for each published package.

## One-time setup

1. **Settings → Actions → General**: allow GitHub Actions to create pull requests.
2. **Settings → Environments**: create `release` with yourself as required reviewer, limited to `trunk`.
3. On npm, give each package a trusted publisher: GitHub Actions, `thomasfosterau/effect-auth`, `release.yml`, environment `release`. All seven packages are on npm with one. A new package needs a placeholder published once by hand, so its npm settings exist, before its trusted publisher can be added: run `scripts/first-publish.sh` (every public package not yet on npm) or `scripts/first-publish.sh <name>` (one still private), which publishes an empty `0.0.0` after you confirm and walks you through the trusted publisher.
4. Protect `trunk`: pull requests and passing CI required.

The publish job stops at the first failure, before anything is tagged. Fix the cause and re-run the failed jobs: versions already on npm, and versions already released on GitHub, are skipped.

`vp run release:pack` publishes nothing, so it is the dry run: `release/manifest.json` lists what the next release would publish. To publish by hand (a recovery, with npm credentials): run it, `vp pm publish release/<tarball> --access public` for each entry in order, then `node scripts/release.ts tag "$(git rev-parse HEAD)"`.
