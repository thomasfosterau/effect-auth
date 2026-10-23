# @thomasfosterau/effect-auth-sql

Driver-agnostic SQL storage for [`@thomasfosterau/effect-auth`](https://www.npmjs.com/package/@thomasfosterau/effect-auth), built on `effect/sql`: one `Layer` that implements the core's store contracts over any `SqlClient`, plus the DDL that creates their tables.

## Install

```bash
pnpm add @thomasfosterau/effect-auth-sql @thomasfosterau/effect-auth effect
```

`effect` (`>=4.0.0-rc.118`) is a peer dependency. Add a `SqlClient` driver for a [supported dialect](#dialects) at the same version as `effect` (for example `@effect/sql-pg`); this package bundles none.

## Usage

```typescript
import { Effect, Layer } from "effect";
import type { SqlClient } from "effect/sql";
import * as Auth from "@thomasfosterau/effect-auth";
import * as AuthSql from "@thomasfosterau/effect-auth-sql";

// `SqlLive` is any layer providing `SqlClient` for a supported dialect (SQLite, D1, PostgreSQL).
export const makeAuth = (SqlLive: Layer.Layer<SqlClient.SqlClient>) => {
  // Creates the `auth_*` tables; idempotent, so it is safe on every deploy.
  const migrate = AuthSql.migrate.pipe(Effect.provide(SqlLive));

  const sessionConfig: Auth.SessionConfig = {
    sessionExpiresIn: { activePeriod: 30 * 86_400_000, idlePeriod: 14 * 86_400_000 },
  };
  const AuthLive = Auth.SessionService.layer(sessionConfig).pipe(
    Layer.provideMerge(Layer.mergeAll(AuthSql.layer, Auth.Hooks.Default)),
    Layer.provide(SqlLive),
  );
  return { migrate, AuthLive };
};
```

`AuthSql.layer` provides every store below at once, so any service built over them (`EmailPasswordService`, `OAuthService`, `WebAuthnService`, `MagicLinkService`, `MultiFactorService`, `ApiKeyService`, `AdminService`, …) has persistence once it is composed on top.

## Stores

`layer` is `Layer<…every store…, never, SqlClient>`. Each store is also available on its own, as an `Effect` that builds it (`make<Name>`) and as a `Layer` (`<Name>Layer`), for wiring a subset:

| Store (core tag)                           | Constructor / layer                                            | Table                       |
| ------------------------------------------ | -------------------------------------------------------------- | --------------------------- |
| `Auth.SessionStore`                        | `makeSessionStore` / `SessionStoreLayer`                       | `auth_sessions`             |
| `Auth.UserStore`                           | `makeUserStore` / `UserStoreLayer`                             | `auth_users`                |
| `Auth.UserServiceStore`                    | `makeUserServiceStore` / `UserServiceStoreLayer`               | `auth_users`                |
| `Auth.IdentifierStore`                     | `makeIdentifierStore` / `IdentifierStoreLayer`                 | `auth_identifiers`          |
| `Auth.Email.EmailPasswordStore`            | `makeEmailPasswordStore` / `EmailPasswordStoreLayer`           | `auth_users`                |
| `Auth.Email.EmailVerificationStore`        | `makeEmailVerificationStore` / `EmailVerificationStoreLayer`   | `auth_email_verifications`  |
| `Auth.Email.EmailOtpStore`                 | `makeEmailOtpStore` / `EmailOtpStoreLayer`                     | `auth_email_otps`           |
| `Auth.Email.EmailOtpUserStore`             | `makeEmailOtpUserStore` / `EmailOtpUserStoreLayer`             | `auth_users`                |
| `Auth.Password.PasswordResetStore`         | `makePasswordResetStore` / `PasswordResetStoreLayer`           | `auth_password_resets`      |
| `Auth.Password.PasswordResetUserStore`     | `makePasswordResetUserStore` / `PasswordResetUserStoreLayer`   | `auth_users`                |
| `Auth.MagicLinkStore`                      | `makeMagicLinkStore` / `MagicLinkStoreLayer`                   | `auth_magic_links`          |
| `Auth.MagicLinkUserStore`                  | `makeMagicLinkUserStore` / `MagicLinkUserStoreLayer`           | `auth_users`                |
| `Auth.RateLimitStore`                      | `makeRateLimitStore` / `RateLimitStoreLayer`                   | `auth_rate_limits`          |
| `Auth.MultiFactor.ChallengeStore`          | `makeChallengeStore` / `ChallengeStoreLayer`                   | `auth_webauthn_challenges`  |
| `Auth.MultiFactor.CredentialStore`         | `makeCredentialStore` / `CredentialStoreLayer`                 | `auth_webauthn_credentials` |
| `Auth.MultiFactor.MultiFactorStore`        | `makeMultiFactorStore` / `MultiFactorStoreLayer`               | `auth_multi_factor`         |
| `Auth.MultiFactor.PendingMultiFactorStore` | `makePendingMultiFactorStore` / `PendingMultiFactorStoreLayer` | `auth_pending_multi_factor` |
| `Auth.OAuth.OAuthStateStore`               | `makeOAuthStateStore` / `OAuthStateStoreLayer`                 | `auth_oauth_states`         |
| `Auth.OAuth.OAuthAccountStore`             | `makeOAuthAccountStore` / `OAuthAccountStoreLayer`             | `auth_oauth_accounts`       |
| `Auth.OAuth.OAuthUserStore`                | `makeOAuthUserStore` / `OAuthUserStoreLayer`                   | `auth_users`                |
| `Auth.Plugins.AccountLockoutStore`         | `makeAccountLockoutStore` / `AccountLockoutStoreLayer`         | `auth_account_lockouts`     |
| `Auth.ApiKeyStore`                         | `makeApiKeyStore` / `ApiKeyStoreLayer`                         | `auth_api_keys`             |
| `Auth.AdminUserStore`                      | `makeAdminUserStore` / `AdminUserStoreLayer`                   | `auth_users`                |

```typescript
import { Layer } from "effect";
import type { SqlClient } from "effect/sql";
import * as AuthSql from "@thomasfosterau/effect-auth-sql";

// Only sessions, users and identifiers, on top of an existing `SqlClient` layer.
export const coreStores = (SqlLive: Layer.Layer<SqlClient.SqlClient>) =>
  Layer.mergeAll(
    AuthSql.SessionStoreLayer,
    AuthSql.UserStoreLayer,
    AuthSql.IdentifierStoreLayer,
  ).pipe(Layer.provide(SqlLive));
```

Not covered yet: the stores added to the core later (one-time tokens, trusted devices, phone OTP, organizations, the OIDC provider, SSO, device authorization). Implement those contracts yourself for now. (The core's `KeyValueStore`-backed layers, `OAuthStateStoreKV`, `ChallengeStoreKV`, `RateLimitStoreKV` and the rest, cover only the short-lived stores, not these.)

## Schema and migration

- `schemaStatements: readonly string[]` — the ordered DDL, one statement per entry, every one `CREATE TABLE IF NOT EXISTS` or `CREATE [UNIQUE] INDEX IF NOT EXISTS` over `auth_`-prefixed tables, so they live beside your own.
- `migrate: Effect<void, Auth.AuthError, SqlClient>` — runs `schemaStatements` through the ambient `SqlClient`. Safe on every deploy and every cold start.

Storage format: instants are epoch milliseconds in `BIGINT` columns (past 2038 on every engine), booleans `0`/`1`, attribute bags JSON `TEXT`, binary values (WebAuthn challenges and public keys) base64 `TEXT`. Token columns (`auth_sessions.id`, the magic-link, verification and reset tokens, `auth_api_keys.key_hash`) hold the SHA-256 digest the service layer computed: the database never sees a raw bearer token.

- `purgeExpired: Effect<PurgeExpiredResult, Auth.AuthError, SqlClient>` — deletes the `auth_magic_links` and `auth_email_otps` rows whose `expires_at` has passed (read from the `Clock`) and reports how many went from each. No store deletes them on its own: a code or link nobody redeems stays until a later send for the same address replaces it, and the sends that hide whether an account exists write one for any address, so without a purge those tables grow with every distinct address a caller tries. Schedule it from the host: a cron trigger on Workers, a timer or job on a long-lived server. The services already refuse an expired row, so a purge changes no outcome.

Upserts and counters are single `ON CONFLICT … DO UPDATE` / `UPDATE … RETURNING` statements, so they are atomic without a transaction. Multi-step writes (`ChallengeStore.create`, `OAuthStateStore.create`, `EmailOtpStore.upsert`, `IdentifierStore.replace`) run inside `sql.withTransaction`.

## Authorization

Role data lives in two tables, `auth_user_roles` (user → role) and `auth_role_permissions` (role → `resource` / `action`), but `layer` does not wire authorization: an `EntityResolver` is one slot the application composes, not a store.

- `makeRbacEntityResolver` / `RbacEntityResolverLayer` — an `Auth.EntityResolver` that answers `User::"<id>"` references with a `Role::"<role>"` parent per assigned role. It answers only `User` references and adds no role-to-role edges, so compose it with your own resolver when policies name other entities.
- `readRbacPolicies: Effect<ReadonlyArray<Auth.Policy.DeclarativePolicy>, never, SqlClient>` — reads `auth_role_permissions` and compiles it with `Auth.Rbac.policies`, the same policies a hand-written `Auth.Rbac` configuration produces.

```typescript
import { Effect, Layer } from "effect";
import type { SqlClient } from "effect/sql";
import * as Auth from "@thomasfosterau/effect-auth";
import * as AuthSql from "@thomasfosterau/effect-auth-sql";

export const authorization = (SqlLive: Layer.Layer<SqlClient.SqlClient>) =>
  Layer.unwrap(
    Effect.map(AuthSql.readRbacPolicies, (policies) => Auth.Authorizer.layer({ policies })),
  ).pipe(Layer.provide(AuthSql.RbacEntityResolverLayer), Layer.provide(SqlLive));
```

Policies are read once, when the layer is built; re-read them behind a `PolicyStore` if role edits must apply without a restart.

## Read scopes

`readScopeWhere(scope, { columns, sets? })` renders a core `Auth.ReadScope` as a `WHERE` fragment, so a LIST filters in the database rather than after the fact. `Auth.ReadScope.compile` produces the scope from a policy set (ADR-0020).

```typescript
import { Effect } from "effect";
import { SqlClient } from "effect/sql";
import * as Auth from "@thomasfosterau/effect-auth";
import * as AuthSql from "@thomasfosterau/effect-auth-sql";

export const listPosts = (scope: Auth.ReadScope.ReadScope, viewerId: string) =>
  Effect.gen(function* () {
    const sql = yield* SqlClient.SqlClient;
    const where = yield* AuthSql.readScopeWhere(scope, {
      columns: { owner: sql("owner_id"), visibility: sql("visibility"), draft: sql("draft") },
      sets: { following: sql`SELECT followee FROM follows WHERE follower = ${viewerId}` },
    });
    return yield* sql`SELECT * FROM posts WHERE ${where}`;
  });
```

- `AllowAll` renders `1 = 1` and `Deny` renders `1 = 0`, so the fragment always splices in.
- Every comparison carries an `IS NOT NULL` guard, so a NULL column decides as the core decides an absent attribute and never through SQL's third truth value.
- A named set is a subquery and is never materialised. A set with no fragment in `sets` is dropped with `ReadScope.withoutSets`, which narrows the scope.
- An attribute with no column in `columns` lists nothing.

## Dialects

- **SQLite:** supported. The test suite runs every store over `better-sqlite3`.
- **Cloudflare D1:** supported. D1 is SQLite; [`@thomasfosterau/effect-auth-alchemy`](https://www.npmjs.com/package/@thomasfosterau/effect-auth-alchemy) wires it, and its suite runs these stores over a SQLite-backed D1 shim. D1 has no transactions, so there the multi-step writes are not atomic (see that package's README).
- **PostgreSQL:** supported. The same suite runs over PostgreSQL through PGlite (`@effect/sql-pglite`).
- **MySQL:** not supported ([#260](https://github.com/thomasfosterau/effect-auth/issues/260)). MySQL has no `ON CONFLICT` clause, so the upserts and counters fail. For MySQL, use [`@thomasfosterau/effect-auth-drizzle`](https://www.npmjs.com/package/@thomasfosterau/effect-auth-drizzle) with its MySQL tables (`Drizzle.MySql`). That package covers only `SessionStore`, `UserStore` and `IdentifierStore`, and its MySQL suite runs against `drizzle-orm/mysql-proxy`, not a MySQL server.

## Errors

Every store method fails only with `Auth.AuthError` (an infrastructure failure, the driver's error kept as `cause`); a lookup that finds nothing returns `null`, and the core services turn that into their typed errors. A unique-index violation (an identifier, an OAuth account, an API key hash) is an `AuthError` too, which the core resolves into the domain error (`IdentifierTakenError`, …).

## License

MIT
