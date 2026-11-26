# @thomasfosterau/effect-auth-better-auth

BetterAuth as the backend for the core's services: `BetterAuthSessions` (the request lookup), the core's `SessionService`, `UserStore`, `UserServiceStore`, `AccountDeletion` and a read-only `IdentifierStore` over a BetterAuth instance, the thin `BetterAuthCredentials` sign-in wrapper and a scrypt `PasswordHasher` over `better-auth/crypto`. It is stage 1 of the [BetterAuth migration](../../docs/guides/better-auth-migration.md): the app keeps BetterAuth's runtime, tables and routes.

## Boundary

Archetype **Backend adapter** (`.fallowrc.json` zone `backend-adapters`, which may import `core` and `ladder`; [ADR-0022](../../docs/adr/0022-package-boundaries.md)'s "Applied" list). It is a package because `better-auth` is a dependency the core lacks. Peers: `better-auth` (`catalogs.better-auth-peers`) and `effect` (`catalog:peers`). Depends on `@thomasfosterau/effect-auth` only. `"private": true` until the owner sets up npm, so the Release workflow skips it. `SvelteKit.test.ts` alone may import `@thomasfosterau/effect-auth-sveltekit` (a dev dependency, its own fallow zone).

## Invariants

- **`$context` is read in one place**: `BetterAuthInstance.layer` resolves `auth.$context` once, and everything else takes the resolved context from that service. The internal adapter is not documented as stable, so its use stays behind the structural types in `BetterAuth.ts`, which the suites type-check against the catalog's `better-auth` (the plugin-augmented instance in `src/testing/Fixtures.ts` must keep fitting `BetterAuthLike`).
- **The token never reaches a domain value.** `Session.id` is BetterAuth's stored `session.id`; `toSession` drops `token`. `revokeSessionById`, `revokeOtherSessions` and `setSessionAttributes` take the stored id; `validateSession` and `invalidateSession` take the raw (unsigned) token.
- **A lookup fault is a fault.** `lookup` fails with `AuthError` when `getSession` rejects, never reads as anonymous; the `handle`'s `failure` policy decides. A `null` from BetterAuth (no cookie, bad signature, expired) is anonymous.
- **Bans hold as in the core.** `lookup` reads a banned or SCIM-deactivated user as anonymous and `validateSession` fails with `UserBannedError` (`banned`, until `banExpires`).
- **Writes that would bypass BetterAuth's checks are refused**: `IdentifierStore.create` (`IdentifierRefusedError`), `replace`, `delete`, `deleteByUser` (`AuthError`), and `createSession`. Only `setVerified` writes an identifier column. Never add an email or phone write here: it would skip BetterAuth's verification.
- **Only declared columns are written.** `setSessionAttributes` writes a session column BetterAuth declares and does not own (`PROTECTED_SESSION_COLUMNS`); `UserServiceStore.update` writes only the fields that changed, each a declared user column outside `PROTECTED_USER_COLUMNS`. Anything else fails with `AuthError`. A `Date` column read as epoch milliseconds is never written back unless it changed.
- **`APIError` is mapped by status and `body.code`** (`fromApiError`), structurally, without importing BetterAuth's error class; anything else is `AuthError` with the cause kept. BetterAuth's duplicate sign-up code is `USER_ALREADY_EXISTS_USE_ANOTHER_EMAIL` in 1.7.28 (matched by prefix).
- **Tests run a real in-memory BetterAuth** (`memoryAdapter`, no network), not `better-auth/test`, which imports `vitest` directly.
