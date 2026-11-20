# Security

effect-auth is pre-1.0 and **not production-ready**. Only the latest published `0.x` of each package receives fixes.

## Reporting a vulnerability

Don't open a public issue. Email me@thomasfoster.au with what an attacker can do, the affected packages and versions, and a reproduction. Expect a first response within 48 hours. Fixes are developed privately and released before disclosure.

## The security model

What the library guarantees, and what it leaves to the application, is in [ARCHITECTURE.md → Security Considerations](ARCHITECTURE.md#security-considerations).

### The session cookie cache is an authorization bound

`cookie.cache` serves a request from a signed snapshot of the session and user, without reading the store, for up to `maxAge` (default 5 minutes). Within that window a revoked session keeps working on the device holding the cookie, and a changed user is served as it was. A user holding a server-only attribute (`UserServiceConfig.serverOnlyAttributes`, default `["role"]`) is never snapshotted, so a demoted admin's `role` always comes from the store. Keep `maxAge` short.

To invalidate every cache cookie at once, change `cookie.cache.version` and revoke the affected sessions (a valid session is simply re-cached). Without `cookie.cache.encrypt: true` the cookie is signed, not encrypted, so the browser can read what it carries.

## Supply chain

- pnpm holds new versions for 24 hours (`minimumReleaseAge`), runs dependency build scripts only for `allowBuilds`, and installs from a strict catalog with a frozen lockfile. CI runs `pnpm audit --audit-level high`.
- The core depends on nothing but its `effect` peer; its optional peers are reached only from `/http` and `/saml`. Database, framework and native dependencies live in separate packages as peers.
- Workflows default to `permissions: {}`, never persist checkout credentials, and pin actions by tag (locked to commits by `.github/workflows/actions.lock`). CI holds no secrets, so Dependabot PRs run it safely.
- Publishing is npm trusted publishing (OIDC), done by `pnpm publish` with provenance, from the protected `release` environment; there is no `NPM_TOKEN`. Release jobs install with `--ignore-scripts`, so no dependency code runs beside the publish credential ([PUBLISHING.md](PUBLISHING.md)).
