# Security policy

## Supported versions

effect-auth is pre-1.0. Only the latest published `0.x` of each `@thomasfosterau/effect-auth*` package receives security fixes; upgrade with `pnpm update "@thomasfosterau/effect-auth*"`.

## Reporting a vulnerability

Don't open a public issue for a vulnerability. Report it privately to the maintainer at the `author` address in any package's `package.json`.

Include what an attacker can do, the affected packages and versions, and steps or code that reproduce it. You'll get a first response within 48 hours and a triage decision within a week. A fix is developed privately and released before the vulnerability is disclosed; disclosure follows once a fix is available, by agreement with the reporter.

## Supply chain

What the repository does to keep a compromised dependency, action or credential out of what it publishes:

### Dependencies

- **Release-age cooldown.** pnpm refuses to install a version published less than 8 hours ago (`minimumReleaseAge: 480` minutes in [pnpm-workspace.yaml](pnpm-workspace.yaml); only this project's own `@thomasfosterau/*` packages are exempt, via `minimumReleaseAgeExclude`). Dependabot's `cooldown` (`default-days: 1`, same exemption, [.github/dependabot.yml](.github/dependabot.yml)) counts whole days, so it waits longer than pnpm and never proposes a release pnpm would refuse.
- **Install scripts are allow-listed.** pnpm runs a dependency's lifecycle scripts only when `allowBuilds` names it: `better-sqlite3`, `esbuild`, `fallow` and `msgpackr-extract` are allowed, and `workerd` is explicitly denied. Everything else installs without running code.
- **One version of everything, from one catalog.** Every external version lives in the catalog in `pnpm-workspace.yaml`, and `catalogMode: strict` rejects any other specifier. `effect` is forced to a single copy (`overrides`). CI installs with `--frozen-lockfile`, so a drifted lockfile fails rather than resolves.
- **Audit.** CI runs `pnpm audit --audit-level high` on every push and pull request. Advisories in transitive dev-toolchain dependencies are floored with scoped `overrides` (they never reach a published package's dependencies), and Dependabot keeps the catalog and the pinned actions current.
- **Small published graphs.** The core package depends on nothing but its `effect` peer. Native, vendor and database dependencies live in separate packages (Argon2 in `effect-auth-argon2`, the SAML XML stack in `effect-auth-saml`), and database and framework libraries are peers a consumer supplies, never bundled.

### CI

- **Actions are pinned to full commit SHAs** (with the version in a comment), in the workflows and in the shared setup action; Dependabot moves the pins.
- **No default token permissions.** Both workflows declare `permissions: {}`; each job opts into exactly what it needs (`contents: read` for CI).
- **Dependabot-safe CI.** CI needs no secret and no OIDC, so a Dependabot pull request runs it with a read-only token; the release job never runs for `dependabot[bot]`. Every job sets `timeout-minutes`, installs with `--frozen-lockfile`, and calls the local bins through `pnpm exec` rather than a `GITHUB_PATH` entry. Node is `node-version: "*"` with `check-latest: true`, never `latest` (which resolves to a Node pre-release). `uvx zizmor --offline .github` audits the workflows (config in [.github/zizmor.yml](.github/zizmor.yml)).
- **No persisted credentials.** CI's checkouts use `persist-credentials: false`. The release job is the one exception: the Changesets action pushes the version branch and tags with the job-scoped `GITHUB_TOKEN`, so its checkout keeps it.

### Publishing

- **Trusted publishing, no token.** Packages are published from GitHub Actions through npm trusted publishing (OIDC, `id-token: write`); there is no `NPM_TOKEN` secret to steal ([PUBLISHING.md](PUBLISHING.md)).
- **A protected environment.** The release job runs in the `release` GitHub environment, which requires approval, and only on `thomasfosterau/effect-auth` itself, never on a fork.
- **No dependency code runs next to the publish credential.** The release job installs with `--ignore-scripts` and then runs only the repository's own `prepare` script. It sets `pnpm_config_verify_deps_before_run: "false"`, because pnpm 11 would otherwise re-install (with lifecycle scripts) before a `pnpm run` whenever a manifest looked newer than the install, undoing `--ignore-scripts` inside the job that holds `id-token: write`.
- **Pinned npm major.** The job updates npm to `npm@11` (trusted publishing needs `>=11.5.1`), not `@latest`, so a new npm major can't arrive unreviewed.

## The security model

What the library guarantees, what it leaves to the application, and the fail-open trade-off for session resolution are in [docs/ARCHITECTURE.md → Security Considerations](docs/ARCHITECTURE.md#security-considerations).

## The session cookie cache is an authorization bound

`cookie.cache` serves a request from a signed snapshot of the session and user, without reading the store, for up to `maxAge` (default 5 minutes). Within that window:

- **a revoked session keeps working** from its cached cookie on the device that holds it, and
- **a changed user is served as it was** when the cookie was issued.

Authorization-bearing attributes are kept out of the window: a user holding any of `UserService`'s server-only attributes (`UserServiceConfig.serverOnlyAttributes`, default `["role"]`) is never snapshotted, and a cookie carrying one is never served, so a demoted admin's `role` always comes from the store. Keep `maxAge` short regardless.

To invalidate every outstanding cache cookie at once (a role-ladder change, a session-shape change, a suspected compromise), change `cookie.cache.version`, and also revoke the affected accounts' sessions: a still-valid session is simply re-cached under the new version. Without `cookie.cache.encrypt: true` the cookie is signed but not encrypted, so the browser can read the session and user data it carries.
