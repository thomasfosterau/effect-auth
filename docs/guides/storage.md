# Storage

The `KeyValueStore` stores, deleting a user, and SQL storage over `effect/sql` (the `/sql` subpath).

## `KeyValueStore` stores

The core's `*StoreKV` layers run the short-lived stores over any Effect `KeyValueStore`. A `KeyValueStore` has no transactions, unique index or atomic increment, so they split by what survives that:

- **Token and state stores**, bundled as `layerKV`: `OAuthStateStoreKV`, `ChallengeStoreKV`, `EmailVerificationStoreKV`, `PasswordResetStoreKV` and `MagicLinkStoreKV` (and `GoogleOneTapNonceStoreKV` on its own). A lost race on these leaves a record behind or reissues one, which the services tolerate. Their single-use `consume` is atomic within one process; behind several instances it needs a `KeyValueStoreTake` (below).
- **Counter stores, development and single-process only**: `RateLimitStoreKV`, `EmailOtpStoreKV` and `PendingMultiFactorStoreKV`. Their counts are read-modify-write, so across processes parallel guesses or requests share a count and slip past the limit. `layerKVSingleProcess` is `layerKV` plus these three, for development, tests and one process.
- **`IdentifierStoreKV`, development and single-process only**: with no unique index, two processes can both claim one address.

In production, take the counter stores and `IdentifierStore` from `./sql` (or another store with atomic counters and a unique constraint). Keep every `*StoreKV` layer on a strongly consistent backend: an eventually consistent one such as Cloudflare KV can hand a spent token, state or challenge out again. There is no `KeyValueStore` session store.

A `KeyValueStore` has no get-and-delete, so by default each single-use store's `consume` reads and removes under a semaphore the store owns, and two instances sharing one backend can both spend one OAuth state or token. `KeyValueStoreTake` is the missing primitive: provide it beside the `KeyValueStore`, over the same backend, and every `consume` takes its record with one atomic `take(key)` call. Over Redis it is `GETDEL`; on Cloudflare, a Durable Object, or use D1 through `./sql`. `layerMemoryKeyValueStore` (and so `Testing.memoryStores`) provides one.

```ts
import { Effect, Layer } from "effect";
import * as Auth from "@thomasfosterau/effect-auth";

// `redis` is your client, the same one behind the `KeyValueStore`.
declare const redis: { getDel(key: string): Promise<string | null> };

export const RedisTake = Layer.succeed(Auth.KeyValueStores.KeyValueStoreTake, {
  take: (key) =>
    Effect.tryPromise({
      try: async () => (await redis.getDel(key)) ?? undefined,
      catch: (cause) => new Auth.Errors.AuthError({ message: "GETDEL failed", cause }),
    }),
});
// Auth.KeyValueStores.layerKV.pipe(Layer.provide(Layer.merge(RedisKeyValueStore, RedisTake)))
```

`take` must name keys as the `KeyValueStore` does: behind a `KeyValueStore.prefix` view, add the prefix before calling the backend.

No store deletes an expired record on its own, and most are written for unauthenticated requests: an OAuth state per authorize redirect, a WebAuthn challenge per begin, a rate-limit row per key counted, a lockout row per identifier tried, and a code or link per send (the sends that hide whether an account exists write one for any address). The services refuse an expired record, so this is about space, not access, but without a purge a caller can grow the store by one record per request. Purge on a schedule the host owns (a cron trigger on Workers, a timer or job on a long-lived server):

- `@thomasfosterau/effect-auth/sql`'s `purgeExpired` (and the Alchemy packages' `purgeExpired`) deletes every expired row, one statement per table: sessions, OAuth states, WebAuthn challenges, pending second factors, email verifications, password resets, magic links and email OTPs past `expires_at`; rate-limit rows once their window and block have both passed; account-lockout rows once their lock has ended or, never locked, after a day without an attempt; email-OTP failure budgets 25 hours after their latest wrong code. **Expired sessions are purged too**: `validateSession` already refuses and deletes one, so keep your own record if you need session history. `purgeExpiredWith` takes the two retentions (`accountLockoutRetention`, `otpFailureRetention`; keep them at least your `lockoutDurationMs` and `backoff.maxDelay`) and a `limit` for a cron with a CPU budget, which caps each table and reports the counts, so loop until they are `0`. `@thomasfosterau/effect-auth-drizzle`'s `RateLimitStore.purgeExpired(tables)` covers its rate-limit table, and `purgeExpired(tables, { limit })` reports no counts, so run a fixed number of calls per tick.
- `purgeExpiredKV` does the same for every `*StoreKV` layer (so `layerKV`, `layerKVSingleProcess` and `Testing.memoryStores`), over their own key prefixes only. `KeyValueStore` has no per-entry TTL, so each expiring record is written in an expiry envelope the purge reads, and a rate-limit entry also outlives the TTL it was set with. It finds the records through the store's own `keys` (Effect 4.1), so any `KeyValueStore` serves, `KeyValueStore.layerMemory` included. A backend that lists by prefix more cheaply than it lists everything (a large or shared Workers KV namespace, Redis) can also provide `KeyValueStoreKeys`, whose `list(prefix)` the purge then uses instead; `layerMemoryKeyValueStore` provides both over one in-memory map. `purgeExpiredKVWith({ otpFailureRetention })` sets the failure-budget retention.
- The in-process stores bound themselves: `memoryAccountLockoutStore`, `memorySamlReplayStore`, the OIDC provider's consumed-refresh-token registry and `AnonymousService`'s record of completed links drop their spent entries each time they double in size.

```ts
import { Effect, Layer } from "effect";
import * as Auth from "@thomasfosterau/effect-auth";

// Optional, for Workers KV: list one prefix, following every cursor. `KV` is the namespace binding.
export const workersKvKeys = (KV: {
  list: (options: { prefix: string; cursor?: string }) => Promise<{
    keys: ReadonlyArray<{ name: string }>;
    list_complete: boolean;
    cursor?: string;
  }>;
}) =>
  Layer.succeed(Auth.KeyValueStores.KeyValueStoreKeys, {
    list: (prefix) =>
      Effect.tryPromise({
        try: async () => {
          const names: Array<string> = [];
          let cursor: string | undefined;
          do {
            const page = await KV.list(cursor === undefined ? { prefix } : { prefix, cursor });
            names.push(...page.keys.map((key) => key.name));
            cursor = page.list_complete ? undefined : page.cursor;
          } while (cursor !== undefined);
          return names;
        },
        catch: () => new Auth.Errors.AuthError({ message: "KV list failed" }),
      }),
  });

// In the scheduled handler, with the same KeyValueStore the stores use:
// yield* Auth.KeyValueStores.purgeExpiredKV  // { oauthStates, magicLinks, emailOtps, rateLimits, … }
```

The listing must name keys as the `KeyValueStore` sees them: behind a `KeyValueStore.prefix` view, strip that prefix. The KV purge is read-then-delete like the stores' other multi-step writes, so an OTP re-sent for the same address and purpose mid-purge can be deleted with the expired one; that code is then refused and the user asks for another.

## Deleting a user

Deleting a user deletes everything the account holds. Every path that deletes a user runs one purge: `AccountManagementService.confirmAccountDeletion` (after its `beforeDelete` hook; `POST /account-deletions/redemptions`), `AdminService.removeUser` (`DELETE /admin/users/:id`), `AnonymousService.linkAccount` (the guest it upgrades), and `UserService.deleteUser`, which delegates to the `AccountDeletion` service (provide `accountDeletionLayer` beside `UserService`; without it `deleteUser` fails with `AuthError` and deletes nothing). SCIM's `DELETE /Users/:id` deactivates a user and deletes nothing. The purge runs in this order:

1. the credentials and tokens, through each user-keyed store's per-user delete: OAuth links (`OAuthAccountStore.deleteByUserId`, their provider tokens with them), passkeys (`CredentialStore.deleteByUserId`), API keys (`ApiKeyStore.deleteByUserId`), the TOTP enrolment and backup codes (`MultiFactorStore.delete`), trusted devices, the OIDC provider's access and refresh tokens and the user's consents (`OidcTokenStore` / `OidcConsentStore.deleteByUserId`), pending password resets and email verifications, and pending account-management tokens;
2. the unspent magic links and email and phone one-time codes sent to the user's addresses (`MagicLinkStore.deleteByEmail`, `EmailOtpStore.delete` / `PhoneOtpStore.delete` for every purpose), which are keyed by address: left in place, one would sign its holder into whatever account claims the address next. The codes' failure budgets stay with the address;
3. the sessions;
4. the identifiers, so the user's addresses and handles can be claimed again (`removeUser` used to leave them): the same email signs up as a new account, and nothing sent to the deleted one (a reset or verification link, a magic link, a code) works for it;
5. the user row (`UserServiceStore.delete`), last.

Each store is used when it is in the context the service's layer is built in, as for the first proof of an address: an app without passkeys provides no `CredentialStore`, and its users hold none. A credential store that is not in that context is skipped silently, and its rows for the user survive the deletion, so build the deleting layer over every store the app uses. The library adds no foreign keys. Because the user row goes last, a failure part-way leaves the user (with some of what it held already gone), never rows that name a user who no longer exists; every step is idempotent, so calling `removeUser` again finishes the job (a self-service deletion needs a new token, since its own was deleted in step 1). That includes a failure after step 4, which leaves a user row with no identifiers that nobody can sign in to: an admin retry with `removeUser` deletes it. The steps run in the caller's fiber with no transaction of their own: on `./sql`, wrap the call in `sql.withTransaction` (the stores' statements join it; on D1 that is a batch) to make the deletion atomic, and on effect-auth-drizzle use an Effect driver's `db.transaction`. Only such a surrounding transaction closes the window between step 2 and step 4, in which the identifiers still name the user but the codes proving its addresses are already gone.

`ApiKeyService.verify` (and `verifyWithRateLimit`) spends a use through `ApiKeyStore.recordUse`, one atomic step that moves only `remaining`, `lastRefillAt`, `lastUsedAt` and `updatedAt`: a verify never writes the record back from its read, so a key its owner disables, narrows or re-expires while a verify is in flight stays that way, and of concurrent verifies of a key with one use left exactly one passes. When the spend finds the key changed since the read, the key is read and checked again, so it is refused for what it now is. A bring-your-own `ApiKeyStore` implements `recordUse` (`applyApiKeyUse` is its contract as a pure function); `apiKeyStoreConformance` checks it, concurrency included.

`ApiKeyService.verify` (and `verifyWithRateLimit`) also refuses a key whose owner `UserStore` no longer finds, answering `Invalid API key` as for an unknown key, so a key that outlived its user (a user row deleted straight through `UserServiceStore.delete`) never authenticates; `ApiKeyService` therefore requires `UserStore`.

`ApiKeyService.check` runs the same lookup and checks as `verify` (owner, enabled, expiry, remaining uses, permissions) and answers the same result, but spends nothing: `remaining`, `lastRefillAt` and `lastUsedAt` stay as they are, nothing is written and no rate-limit token is taken. Use it to re-validate, on every request of a long-lived connection, a key already accepted with `verify`: a key disabled, expired or deleted, or whose owner is banned or SCIM-deactivated, is refused at the next check, and the checks do not use up the key's quota. A key with no uses left is still refused.

JWTs already issued (`Jwt`) cannot be revoked and expire on their own. Short-lived records that carry a user id but are redeemed through a check that loads the user (pending multi-factor and OTP-second-factor challenges, approved device codes, OIDC authorization codes, and one-time tokens: `redeemOneTimeTokenForSession` refuses a token whose subject `UserStore` no longer finds, as an unknown token, so it requires `UserStore`) are left to expire. Organization invitations sent by email are not purged either: they name an address, not the user, and stay until they expire or are accepted, rejected or canceled.

## SQL storage (`/sql`)

Driver-agnostic SQL storage, built on `effect/sql`: one `Layer` that implements the core's store contracts over any `SqlClient`, plus the DDL that creates their tables.

`effect/sql` ships in `effect`, so the subpath adds no dependency. Add a `SqlClient` driver for a [supported dialect](#dialects) at the same version as `effect` (for example `@effect/sql-pg`); the package bundles none. On Alchemy, [`@thomasfosterau/effect-auth-alchemy-cloudflare`](https://github.com/thomasfosterau/effect-auth/tree/trunk/packages/alchemy-cloudflare) (D1) and [`@thomasfosterau/effect-auth-alchemy-postgres`](https://github.com/thomasfosterau/effect-auth/tree/trunk/packages/alchemy-postgres) wire these stores to a database and reconcile the schema on deploy.

### Usage

```typescript
import { Effect, Layer } from "effect";
import type { SqlClient } from "effect/sql";
import * as Auth from "@thomasfosterau/effect-auth";
import * as AuthSql from "@thomasfosterau/effect-auth/sql";

// `SqlLive` is any layer providing `SqlClient` for a supported dialect (SQLite, D1, PostgreSQL).
export const makeAuth = (SqlLive: Layer.Layer<SqlClient.SqlClient>) => {
  // Creates the `auth_*` tables; idempotent, so it is safe on every deploy.
  const migrate = AuthSql.migrate.pipe(Effect.provide(SqlLive));

  const sessionConfig: Auth.Types.SessionConfig = {
    sessionExpiresIn: { activePeriod: 30 * 86_400_000, idlePeriod: 14 * 86_400_000 },
  };
  const AuthLive = Auth.SessionService.SessionService.layer(sessionConfig).pipe(
    Layer.provideMerge(Layer.mergeAll(AuthSql.layer, Auth.Hooks.Hooks.Default)),
    Layer.provide(SqlLive),
  );
  return { migrate, AuthLive };
};
```

`AuthSql.layer` provides every store below at once, so any service built over them (`EmailPasswordService`, `OAuthService`, `WebAuthnService`, `MagicLinkService`, `MultiFactorService`, `ApiKeyService`, `AdminService`, …) has persistence once it is composed on top.

### Stores

`layer` is `Layer<…every store…, never, SqlClient>`. Each store is also available on its own, as an `Effect` that builds it (`make<Name>`) and as a `Layer` (`<Name>Layer`), for wiring a subset:

| Store (core tag)                           | Constructor / layer                                            | Table                                                             |
| ------------------------------------------ | -------------------------------------------------------------- | ----------------------------------------------------------------- |
| `Auth.SessionStore.SessionStore`           | `makeSessionStore` / `SessionStoreLayer`                       | `auth_sessions`                                                   |
| `Auth.UserStore.UserStore`                 | `makeUserStore` / `UserStoreLayer`                             | `auth_users`                                                      |
| `Auth.User.UserServiceStore`               | `makeUserServiceStore` / `UserServiceStoreLayer`               | `auth_users`                                                      |
| `Auth.Identifier.IdentifierStore`          | `makeIdentifierStore` / `IdentifierStoreLayer`                 | `auth_identifiers`                                                |
| `Auth.Email.EmailPasswordStore`            | `makeEmailPasswordStore` / `EmailPasswordStoreLayer`           | `auth_users`                                                      |
| `Auth.Email.EmailVerificationStore`        | `makeEmailVerificationStore` / `EmailVerificationStoreLayer`   | `auth_email_verifications`                                        |
| `Auth.Email.EmailOtpStore`                 | `makeEmailOtpStore` / `EmailOtpStoreLayer`                     | `auth_email_otps`, `auth_email_otp_failures`                      |
| `Auth.Email.EmailOtpUserStore`             | `makeEmailOtpUserStore` / `EmailOtpUserStoreLayer`             | `auth_users`                                                      |
| `Auth.Password.PasswordResetStore`         | `makePasswordResetStore` / `PasswordResetStoreLayer`           | `auth_password_resets`                                            |
| `Auth.Password.PasswordResetUserStore`     | `makePasswordResetUserStore` / `PasswordResetUserStoreLayer`   | `auth_users`                                                      |
| `Auth.MagicLink.MagicLinkStore`            | `makeMagicLinkStore` / `MagicLinkStoreLayer`                   | `auth_magic_links`                                                |
| `Auth.MagicLink.MagicLinkUserStore`        | `makeMagicLinkUserStore` / `MagicLinkUserStoreLayer`           | `auth_users`                                                      |
| `Auth.RateLimit.RateLimitStore`            | `makeRateLimitStore` / `RateLimitStoreLayer`                   | `auth_rate_limits`                                                |
| `Auth.MultiFactor.ChallengeStore`          | `makeChallengeStore` / `ChallengeStoreLayer`                   | `auth_webauthn_challenges`                                        |
| `Auth.MultiFactor.CredentialStore`         | `makeCredentialStore` / `CredentialStoreLayer`                 | `auth_webauthn_credentials`, `auth_webauthn_credential_flags`     |
| `Auth.MultiFactor.MultiFactorStore`        | `makeMultiFactorStore` / `MultiFactorStoreLayer`               | `auth_multi_factor`                                               |
| `Auth.MultiFactor.PendingMultiFactorStore` | `makePendingMultiFactorStore` / `PendingMultiFactorStoreLayer` | `auth_pending_multi_factor`, `auth_pending_multi_factor_attempts` |
| `Auth.OAuth.OAuthStateStore`               | `makeOAuthStateStore` / `OAuthStateStoreLayer`                 | `auth_oauth_states`                                               |
| `Auth.OAuth.OAuthAccountStore`             | `makeOAuthAccountStore` / `OAuthAccountStoreLayer`             | `auth_oauth_accounts`                                             |
| `Auth.OAuth.OAuthUserStore`                | `makeOAuthUserStore` / `OAuthUserStoreLayer`                   | `auth_users`                                                      |
| `Auth.Plugins.AccountLockoutStore`         | `makeAccountLockoutStore` / `AccountLockoutStoreLayer`         | `auth_account_lockouts`                                           |
| `Auth.ApiKey.ApiKeyStore`                  | `makeApiKeyStore` / `ApiKeyStoreLayer`                         | `auth_api_keys`                                                   |
| `Auth.Admin.AdminUserStore`                | `makeAdminUserStore` / `AdminUserStoreLayer`                   | `auth_users`                                                      |

```typescript
import { Layer } from "effect";
import type { SqlClient } from "effect/sql";
import * as AuthSql from "@thomasfosterau/effect-auth/sql";

// Only sessions, users and identifiers, on top of an existing `SqlClient` layer.
export const coreStores = (SqlLive: Layer.Layer<SqlClient.SqlClient>) =>
  Layer.mergeAll(
    AuthSql.SessionStoreLayer,
    AuthSql.UserStoreLayer,
    AuthSql.IdentifierStoreLayer,
  ).pipe(Layer.provide(SqlLive));
```

Not covered yet: the stores added to the core later (one-time tokens, trusted devices, phone OTP, organizations, the OIDC provider, SSO, device authorization). Implement those contracts yourself for now. (The core's `KeyValueStore`-backed layers, `OAuthStateStoreKV`, `ChallengeStoreKV`, `RateLimitStoreKV` and the rest, cover only the short-lived stores, not these.)

### Schema and migration

- `schemaStatements: readonly string[]` — the ordered DDL, one statement per entry, every one `CREATE TABLE IF NOT EXISTS` or `CREATE [UNIQUE] INDEX IF NOT EXISTS` over `auth_`-prefixed tables, so they live beside your own.
- `migrate: Effect<void, Auth.Errors.AuthError, SqlClient>` — runs `schemaStatements` through the ambient `SqlClient`. Safe on every deploy and every cold start.

Storage format: instants are epoch milliseconds in `BIGINT` columns (past 2038 on every engine), booleans `0`/`1`, attribute bags JSON `TEXT`, binary values (WebAuthn challenges and public keys) base64 `TEXT`. Token columns (`auth_sessions.id`, the magic-link, verification and reset tokens, `auth_api_keys.key_hash`) hold the SHA-256 digest the service layer computed: the database never sees a raw bearer token.

- `purgeExpired: Effect<PurgeExpiredResult, Auth.Errors.AuthError, SqlClient>` — deletes every expired row (read from the `Clock`) and reports how many went from each table: `auth_sessions`, `auth_oauth_states`, `auth_webauthn_challenges`, `auth_pending_multi_factor`, `auth_email_verifications`, `auth_password_resets`, `auth_magic_links` and `auth_email_otps` past `expires_at`; `auth_rate_limits` rows whose `reset_at` and `blocked_until` have both passed; `auth_account_lockouts` rows whose lock has ended or which have had no attempt for a day; `auth_email_otp_failures` rows 25 hours after their latest wrong code. The companion tables lose their orphans in the same run. A row inside its window, still blocked or still live stays, so a purge changes no outcome. No store deletes them on its own, so schedule it from the host (see [Expired rows](#sql-storage-sql)).
- `purgeExpiredWith(options?)` — `purgeExpired` with `PurgeExpiredOptions`: `limit` (a positive integer) caps the rows deleted from each table in one run, as `DELETE … WHERE <expired> AND key IN (SELECT key … WHERE <expired> LIMIT n)` (the outer `<expired>` keeps a row refreshed concurrently after the subquery picked it), so a Workers cron tick does bounded work; call it until every count is `0`, or once per tick. `accountLockoutRetention` and `otpFailureRetention` (`Duration.Input`) set how long an idle lockout counter and a failure budget outlive their latest attempt. Omitted, it is `purgeExpired`. A `limit` that is not a positive integer, or a negative or infinite retention, fails with `AuthError` before a statement runs.

Upserts and counters are single `ON CONFLICT … DO UPDATE` / `UPDATE … RETURNING` statements, so they are atomic without a transaction, and `OAuthStateStore.consume` and the single-use token stores' `consume` (email verification, password reset, magic link, pending multi-factor challenge) are each one `DELETE … RETURNING`, so a state or token is handed out once; `MultiFactorStore.useTotpCounter` / `useBackupCode` are compare-and-set `UPDATE … RETURNING`s. Multi-step writes (`ChallengeStore.create` and `.delete`, which keep the ceremony in `auth_webauthn_challenge_ceremonies`, `CredentialStore`'s writes, which keep the backup flags and AAGUID in `auth_webauthn_credential_flags`, `OAuthStateStore.create`, `EmailOtpStore.upsert`, `IdentifierStore.replace`) run inside `sql.withTransaction`.

### Authorization

Role data lives in two tables, `auth_user_roles` (user → role) and `auth_role_permissions` (role → `resource` / `action`), but `layer` does not wire authorization: an `EntityResolver` is one slot the application composes, not a store. `UserServiceStore.delete` removes the user's `auth_user_roles` rows with the user row, in one transaction, since no store owns them.

- `makeRbacEntityResolver` / `RbacEntityResolverLayer` — an `Auth.Authorizer.EntityResolver` that answers `User::"<id>"` references with a `Role::"<role>"` parent per assigned role. It answers only `User` references and adds no role-to-role edges, so compose it with your own resolver when policies name other entities.
- `readRbacPolicies: Effect<ReadonlyArray<Auth.Policy.DeclarativePolicy>, never, SqlClient>` — reads `auth_role_permissions` and compiles it with `Auth.Rbac.policies`, the same policies a hand-written `Auth.Rbac` configuration produces.

```typescript
import { Effect, Layer } from "effect";
import type { SqlClient } from "effect/sql";
import * as Auth from "@thomasfosterau/effect-auth";
import * as AuthSql from "@thomasfosterau/effect-auth/sql";

export const authorization = (SqlLive: Layer.Layer<SqlClient.SqlClient>) =>
  Layer.unwrap(
    Effect.map(AuthSql.readRbacPolicies, (policies) =>
      Auth.Authorizer.Authorizer.layer({ policies }),
    ),
  ).pipe(Layer.provide(AuthSql.RbacEntityResolverLayer), Layer.provide(SqlLive));
```

Policies are read once, when the layer is built; re-read them behind a `PolicyStore` if role edits must apply without a restart.

### Read scopes

`readScopeWhere(scope, { columns, sets? })` renders a core `Auth.ReadScope` as a `WHERE` fragment, so a LIST filters in the database rather than after the fact. `Auth.ReadScope.compile` produces the scope from a policy set (ADR-0020).

```typescript
import { Effect } from "effect";
import { SqlClient } from "effect/sql";
import * as Auth from "@thomasfosterau/effect-auth";
import * as AuthSql from "@thomasfosterau/effect-auth/sql";

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

### Dialects

- **SQLite:** supported. The test suite runs every store over `better-sqlite3`.
- **Cloudflare D1:** supported. D1 is SQLite; [`@thomasfosterau/effect-auth-alchemy-cloudflare`](https://www.npmjs.com/package/@thomasfosterau/effect-auth-alchemy-cloudflare) wires it, and its suite runs these stores over a SQLite-backed D1 shim. D1 has no interactive transactions, so there a transaction's writes are sent as `batch()`es: the writes between two reads commit together, but not across a read (see that package's README).
- **PostgreSQL:** supported. The same suite runs over PostgreSQL through PGlite (`@effect/sql-pglite`).
- **MySQL:** not supported. MySQL has no `ON CONFLICT` clause, so the upserts and counters fail. For MySQL, use [`@thomasfosterau/effect-auth-drizzle`](https://www.npmjs.com/package/@thomasfosterau/effect-auth-drizzle) with its MySQL tables (`Drizzle.MySql`). That package covers only `SessionStore`, `UserStore` and `IdentifierStore`, and its MySQL suite runs against `drizzle-orm/mysql-proxy`, not a MySQL server.

### Errors

Every store method fails only with `Auth.Errors.AuthError` (an infrastructure failure, the driver's error kept as `cause`); a lookup that finds nothing returns `Option.none()`, and the core services turn that into their typed errors. A unique-index violation (an identifier, an OAuth account, an API key hash) is an `AuthError` too, which the core resolves into the domain error (`IdentifierTakenError`, …).
