# Publishing & releases

Releases are automated with [Changesets](https://github.com/changesets/changesets). Publishing is npm trusted publishing (OIDC) from the protected `release` environment; there is no `NPM_TOKEN`. Every non-private package under `packages/` is published from one workflow, [release.yml](./.github/workflows/release.yml). Shape copied from effect-jsonapi (the library reference).

## The release flow

1. **Add a changeset with your change.** Run `pnpm changeset` (or write `.changeset/<slug>.md` by hand), naming every package the change touches with its bump (`patch` / `minor` / `major`) and a user-facing summary, and commit it alongside the change. [AGENTS.md → Branches and pull requests](AGENTS.md#branches-and-pull-requests) says which changes need one.
2. **Merge to `trunk`.** The release workflow runs and, while changesets are pending, opens or updates a **"Version Packages"** PR that applies the version bumps and rolls the changesets into each package's `CHANGELOG.md`.
3. **Merge the "Version Packages" PR.** With no changesets left, the workflow — after the `release` environment's manual approval — publishes every package whose version is not yet on npm via `pnpm publish` and trusted publishing, then tags the commit and creates the GitHub releases.

The publish step uses `pnpm publish`, not `npm publish`: pnpm 11 supports npm OIDC trusted publishing (it mints the short-lived token itself; provenance is left to npm, which attaches it only when allowed, and is never forced because an explicit request fails from a private repository), and it is what rewrites the `catalog:`, `catalog:peers` and `workspace:*` specifiers in each `package.json` into the ranges consumers actually see; npm would publish the literal protocols. `changeset tag` then emits the `New tag:` lines the Changesets action uses to push the tags and create the GitHub releases.

Who may release, and how: [AGENTS.md → Branches and pull requests](AGENTS.md#branches-and-pull-requests).

## Maintainer setup (one-time)

None of the twelve publishable packages is on npm yet. Trusted publishing can only be configured on a package that exists on npm, so the first release needs one bootstrap step:

1. **Allow Actions to open the Version Packages PR.** In the repo: **Settings → Actions → General → Workflow permissions** → enable **"Allow GitHub Actions to create and approve pull requests"**. Without this the built-in `GITHUB_TOKEN` is forbidden from opening pull requests and the workflow fails at the PR-creation step — even though the job already grants `pull-requests: write`.
2. **Create and protect the `release` environment.** **Settings → Environments → New environment → `release`** → enable **Required reviewers** (yourself) and restrict deployment to the `trunk` branch, so publishing pauses for manual approval.
3. **Bootstrap each package name on npm.** For each non-private package under `packages/`, publish a placeholder once from a trusted machine (`pnpm publish --access public` of a `0.0.0` build, or npm's own placeholder flow), so the name exists and its settings page is reachable.
4. **Configure the trusted publisher** for each package. On npmjs.com, open the package → **Settings → Trusted Publisher** and add:
   - Provider: **GitHub Actions**
   - Repository: `thomasfosterau/effect-auth`
   - Workflow: `release.yml`
   - Environment: `release`

   Then remove any classic automation tokens for the package, and delete the repository's `NPM_TOKEN` secret if one exists.

5. **Protect `trunk`.** Require pull requests and passing CI before merge, and disallow direct pushes, so a release can only be triggered by merging the reviewed "Version Packages" PR.
