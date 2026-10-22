# Security policy

## Supported versions

effect-auth is pre-1.0. Only the latest published `0.x` of each `@thomasfosterau/effect-auth*` package receives security fixes; upgrade with `pnpm update "@thomasfosterau/effect-auth*"`.

## Reporting a vulnerability

Don't open a public issue for a vulnerability. Report it privately to the maintainer at the `author` address in any package's `package.json`.

Include what an attacker can do, the affected packages and versions, and steps or code that reproduce it. You'll get a first response within 48 hours and a triage decision within a week. A fix is developed privately and released before the vulnerability is disclosed; disclosure follows once a fix is available, by agreement with the reporter.

## Supply chain

- Every published package is published from CI through npm trusted publishing (OIDC) in the protected `release` environment; there is no `NPM_TOKEN` ([PUBLISHING.md](PUBLISHING.md)).
- The core package depends on `effect` only. Native and vendor dependencies live in separate packages (for example Argon2 in `effect-auth-argon2`, the SAML XML stack in `effect-auth-saml`), as peers where a consumer supplies them.
- CI runs `pnpm audit --audit-level high` on every pull request, and Dependabot keeps the catalog and the pinned actions current.

## The security model

What the library guarantees, what it leaves to the application, and the fail-open trade-off for session resolution are in [docs/ARCHITECTURE.md → Security Considerations](docs/ARCHITECTURE.md#security-considerations).

## The session cookie cache is an authorization bound

`cookie.cache` serves a request from a signed snapshot of the session and user, without reading the store, for up to `maxAge` (default 5 minutes). Within that window:

- **a revoked session keeps working** from its cached cookie on the device that holds it, and
- **a changed user is served as it was** when the cookie was issued.

Authorization-bearing attributes are kept out of the window: a user holding any of `UserService`'s server-only attributes (`UserServiceConfig.serverOnlyAttributes`, default `["role"]`) is never snapshotted, and a cookie carrying one is never served, so a demoted admin's `role` always comes from the store. Keep `maxAge` short regardless.

To invalidate every outstanding cache cookie at once (a role-ladder change, a session-shape change, a suspected compromise), change `cookie.cache.version`, and also revoke the affected accounts' sessions: a still-valid session is simply re-cached under the new version. Without `cookie.cache.encrypt: true` the cookie is signed but not encrypted, so the browser can read the session and user data it carries.
