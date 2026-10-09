# Bring your own store

effect-auth's core (`@thomasfosterau/effect-auth`) depends on `effect` alone — no database driver, no ORM. Every place a feature needs to read or write something durable, it asks for a small `Context.Service` contract instead: `SessionStore`, `UserStore`, `OAuthAccountStore`, and so on. This is the library's answer to "do you support Prisma/Kysely/Mongo?" — you implement the contracts your app uses, over whatever client you already have, and every feature built on them lights up.

If your database is SQLite or Cloudflare D1 (via `effect/sql`), or Postgres or MySQL (via Drizzle), a ready-made implementation already exists (§6) — reach for one of those before writing your own. This guide is for everyone else: Mongo, DynamoDB, Prisma, a REST backend, whatever `db` client you already have.

## 1. Conventions every store follows

All 42 store contracts in core (§5) share the same shape, so once you've implemented one the rest are the same exercise:

- **A contract is a plain object typed `typeof Auth.XStore.Service`.** There's nothing to extend or subclass — write an object whose methods match the interface and provide it with `Layer.succeed(Auth.XStore)(impl)`. (`SessionStore` and `UserStore` live at the package root; a handful of contracts are namespaced — `Auth.Email.*`, `Auth.OAuth.*`, `Auth.Password.*`, `Auth.Plugins.*`, `Auth.MultiFactor.*` — see the exact path in §5.)
- **Lookups return `null` on a miss, never throw or fail.** A service converts `null` into a typed domain error (`SessionNotFoundError`, `UserNotFoundError`, …) at its own layer — the store just reports what it found.
- **Deletes of an unknown id are no-ops**, not errors. `deleteByUserId`/ `deleteByEmail`-style bulk deletes succeed (silently) when there's nothing to delete.
- **Infrastructure failures become `Errors.AuthError`, with `cause` set to the original error.** Every store method's error channel is `AuthError` (or `never` for the couple of methods that are documented as always succeeding). Wrap your driver calls with `Effect.tryPromise`/`Effect.try` and map failures through `new Errors.AuthError({ message: "...", cause })` — never let a driver exception surface as an unhandled defect, and never drop `cause` (it's what makes a production incident readable).
- **Domain records use real `Date` objects and plain JS values at the store boundary.** `User`, `Session`, and `Identifier` are `Schema.Struct`s with `Schema.Date` fields and a `Schema.Record` `attributes` bag — your store receives and must return actual `Date`s and a plain object, not driver-specific types. Codec choice is yours: `packages/sql` stores dates as epoch-millisecond integers and `attributes` as a JSON `TEXT` column; `packages/drizzle` keeps native column types per dialect (`timestamptz`/`jsonb` on Postgres) and lets the driver round-trip them directly. Pick whatever your database does best and convert at the edges of your store implementation.
- **Bearer secrets are handed to you pre-hashed.** Session ids, magic-link/ verification/reset/one-time tokens, API keys, and OIDC codes/tokens are all SHA-256 hex digests (`hashToken` in `TokenHash.ts`) by the time they reach a store — the raw secret is never persisted, so your store just indexes on the digest string like any other primary key. You don't need to hash anything yourself.

## 2. Atomicity: what MUST be a single indivisible operation

Most store methods are ordinary CRUD and tolerate a read-then-write implementation. A few are security-load-bearing and **must** be one atomic operation (a single `UPDATE ... RETURNING`/`INSERT ... ON CONFLICT` statement, a conditional delete, a compare-and-swap — whatever your backend's equivalent is) because a read-modify-write race there is directly exploitable, not just a minor undercount:

- **`AccountLockoutStore.registerAttempt`** (`src/plugins/AccountLockout.ts`). The whole failures-in/lock-out transition — active lock unchanged, expired lock resets to 1, otherwise increment, crossing `maxAttempts` sets `lockedUntil` — must happen in one statement. A read-modify-write implementation lets concurrent sign-in attempts race the counter and undercounts failures, which weakens the brute-force protection the whole feature exists to provide. `packages/sql`'s implementation (`makeAccountLockoutStore`) is a single `INSERT ... ON CONFLICT(key) DO UPDATE` with the whole transition encoded in `CASE` expressions — copy that shape.
- **`SamlReplayStore.consume`** (`src/Saml.ts`). Must be an atomic get-and-delete: two concurrent callers passing the same assertion/request id must not both receive the record — the loser gets `null`. This is the one-time-use replay guard for SAML AuthnRequest and assertion ids; a non-atomic implementation reopens the replay window the store exists to close. Implement it as a conditional `DELETE ... RETURNING` (or compare-and-swap), the same way `DeviceAuthorizationStore.claimApproval` does.
- **`DeviceAuthorizationStore.claimApproval`** (`src/DeviceAuthorization.ts`). Must atomically consume an approved record: if it exists and is `"approved"`, delete it and return it; otherwise return `null`. Two concurrent polls on the same approved `device_code` must each see at most one win — a read-then-delete implementation lets both polls mint a session from the same approval.
- **`IdentifierStore`'s `(type, value)` uniqueness** (`src/Identifier.ts`). `create` isn't itself required to be a single statement, but the `(type, value)` pair _must_ be enforced unique by the store (a real unique index/constraint), not just checked in application code first. The `claimIdentifier` helper's race-repair logic depends on a concurrent duplicate `create` actually failing — it re-checks `getByValue` after a failed `create` and only then decides between "someone beat you to this email" (`IdentifierTakenError`) and a genuine infrastructure error. Without a real unique constraint, two concurrent sign-ups can both claim the same email.

A second tier is **strongly recommended** atomic (packages/sql and packages/alchemy both treat these as single `INSERT ... ON CONFLICT ... DO UPDATE` / `UPDATE ... RETURNING` statements, never a separate SELECT then write): `RateLimitStore.set`/`increment`, `Auth.OAuth.OAuthAccountStore`'s link-or-update path, `Auth.MultiFactor.MultiFactorStore.upsert`, and the `Email`/`PhoneOtpStore` `upsert`/`incrementAttempts` pair. A race here just double-counts an OTP attempt or drops a rate-limit tick — annoying, not a security bypass — so a read-modify-write implementation is a legitimate starting point, but reach for a real atomic statement once your driver supports one. The `KeyValueStore`-backed defaults in `KeyValueStores.ts` document taking the read-modify-write shortcut here deliberately, for exactly this reason.

## 3. Worked example: SessionStore + UserStore + IdentifierStore

The three contracts every credential-based sign-in flow touches, over an imaginary async `db` client (`db.query(sql, params)` returns rows, `db.execute(sql, params)` returns nothing):

```ts
import { Effect, Layer } from "effect";
import * as Auth from "@thomasfosterau/effect-auth";

// Your driver — swap for pg/mysql2/mongodb/whatever you actually have.
declare const db: {
  query: <Row>(sql: string, params: readonly unknown[]) => Promise<Row[]>;
  execute: (sql: string, params: readonly unknown[]) => Promise<void>;
};

const infra =
  (label: string) =>
  (cause: unknown): Auth.AuthError =>
    new Auth.AuthError({ message: `${label} failed`, cause });

// ---------------------------------------------------------------------------
// SessionStore — session.id is always the SHA-256 hash of the bearer token.
// ---------------------------------------------------------------------------

interface SessionRow {
  id: string;
  user_id: string;
  expires_at: number;
  created_at: number;
  last_activity_at: number;
  attributes: string;
}

const rowToSession = (row: SessionRow): Auth.Session => ({
  id: row.id,
  userId: row.user_id,
  expiresAt: new Date(row.expires_at),
  createdAt: new Date(row.created_at),
  lastActivityAt: new Date(row.last_activity_at),
  attributes: JSON.parse(row.attributes),
});

const sessionStore: typeof Auth.SessionStore.Service = {
  create: (session) =>
    Effect.tryPromise({
      try: () =>
        db.execute(
          `INSERT INTO sessions (id, user_id, expires_at, created_at, last_activity_at, attributes)
           VALUES (?, ?, ?, ?, ?, ?)`,
          [
            session.id,
            session.userId,
            session.expiresAt.getTime(),
            session.createdAt.getTime(),
            session.lastActivityAt.getTime(),
            JSON.stringify(session.attributes),
          ],
        ),
      catch: infra("session.create"),
    }).pipe(Effect.as(session)),

  get: (sessionId) =>
    Effect.tryPromise({
      try: () => db.query<SessionRow>("SELECT * FROM sessions WHERE id = ?", [sessionId]),
      catch: infra("session.get"),
    }).pipe(Effect.map((rows) => (rows[0] ? rowToSession(rows[0]) : null))),

  update: (session) =>
    Effect.tryPromise({
      try: () =>
        db.execute(
          `UPDATE sessions SET expires_at = ?, last_activity_at = ?, attributes = ? WHERE id = ?`,
          [
            session.expiresAt.getTime(),
            session.lastActivityAt.getTime(),
            JSON.stringify(session.attributes),
            session.id,
          ],
        ),
      catch: infra("session.update"),
    }).pipe(Effect.as(session)),

  delete: (sessionId) =>
    Effect.tryPromise({
      try: () => db.execute("DELETE FROM sessions WHERE id = ?", [sessionId]),
      catch: infra("session.delete"),
    }).pipe(Effect.asVoid),

  deleteByUserId: (userId) =>
    Effect.tryPromise({
      try: () => db.execute("DELETE FROM sessions WHERE user_id = ?", [userId]),
      catch: infra("session.deleteByUserId"),
    }).pipe(Effect.asVoid),

  listByUserId: (userId) =>
    Effect.tryPromise({
      try: () => db.query<SessionRow>("SELECT * FROM sessions WHERE user_id = ?", [userId]),
      catch: infra("session.listByUserId"),
    }).pipe(Effect.map((rows) => rows.map(rowToSession))),
};

// ---------------------------------------------------------------------------
// UserStore — read-only: `get` resolves a user by id. Password hashes are
// not part of this contract; the shipped EmailPassword flow reads and
// writes its hash through `Auth.Email.EmailPasswordStore` instead.
// ---------------------------------------------------------------------------

interface UserRow {
  id: string;
  name: string | null;
  image: string | null;
  created_at: number;
  updated_at: number;
  attributes: string;
}

const rowToUser = (row: UserRow): Auth.User => ({
  id: row.id,
  ...(row.name !== null ? { name: row.name } : {}),
  ...(row.image !== null ? { image: row.image } : {}),
  createdAt: new Date(row.created_at),
  updatedAt: new Date(row.updated_at),
  attributes: JSON.parse(row.attributes),
});

const userStore: typeof Auth.UserStore.Service = {
  get: (userId) =>
    Effect.tryPromise({
      try: () => db.query<UserRow>("SELECT * FROM users WHERE id = ?", [userId]),
      catch: infra("user.get"),
    }).pipe(Effect.map((rows) => (rows[0] ? rowToUser(rows[0]) : null))),
};

// ---------------------------------------------------------------------------
// IdentifierStore — email/username/phone claims. `(type, value)` MUST be a
// real unique constraint (see §2) — `claimIdentifier` relies on `create`
// failing when a concurrent claim wins the race.
// ---------------------------------------------------------------------------

interface IdentifierRow {
  id: string;
  user_id: string;
  type: string;
  value: string;
  verified: number;
  verified_at: number | null;
  created_at: number;
}

const rowToIdentifier = (row: IdentifierRow): Auth.Identifier => ({
  id: row.id,
  userId: row.user_id,
  type: row.type as Auth.IdentifierType,
  value: row.value,
  verified: row.verified !== 0,
  ...(row.verified_at !== null ? { verifiedAt: new Date(row.verified_at) } : {}),
  createdAt: new Date(row.created_at),
});

const identifierStore: typeof Auth.IdentifierStore.Service = {
  getByValue: (type, value) =>
    Effect.tryPromise({
      try: () =>
        db.query<IdentifierRow>("SELECT * FROM identifiers WHERE type = ? AND value = ?", [
          type,
          value,
        ]),
      catch: infra("identifier.getByValue"),
    }).pipe(Effect.map((rows) => (rows[0] ? rowToIdentifier(rows[0]) : null))),

  listByUser: (userId) =>
    Effect.tryPromise({
      try: () =>
        db.query<IdentifierRow>(
          "SELECT * FROM identifiers WHERE user_id = ? ORDER BY created_at ASC",
          [userId],
        ),
      catch: infra("identifier.listByUser"),
    }).pipe(Effect.map((rows) => rows.map(rowToIdentifier))),

  create: (identifier) =>
    // The UNIQUE(type, value) index does the real work: a concurrent claim
    // makes this INSERT fail, and `claimIdentifier` turns that failure into
    // `IdentifierTakenError` after re-checking `getByValue`.
    Effect.tryPromise({
      try: () =>
        db.execute(
          `INSERT INTO identifiers (id, user_id, type, value, verified, verified_at, created_at)
           VALUES (?, ?, ?, ?, ?, ?, ?)`,
          [
            identifier.id,
            identifier.userId,
            identifier.type,
            identifier.value,
            identifier.verified ? 1 : 0,
            identifier.verifiedAt?.getTime() ?? null,
            identifier.createdAt.getTime(),
          ],
        ),
      catch: infra("identifier.create"),
    }).pipe(Effect.as(identifier)),

  setVerified: (id, verifiedAt) =>
    Effect.tryPromise({
      try: async () => {
        await db.execute("UPDATE identifiers SET verified = 1, verified_at = ? WHERE id = ?", [
          verifiedAt.getTime(),
          id,
        ]);
        return db.query<IdentifierRow>("SELECT * FROM identifiers WHERE id = ?", [id]);
      },
      catch: infra("identifier.setVerified"),
    }).pipe(Effect.map((rows) => (rows[0] ? rowToIdentifier(rows[0]) : null))),

  delete: (id) =>
    Effect.tryPromise({
      try: () => db.execute("DELETE FROM identifiers WHERE id = ?", [id]),
      catch: infra("identifier.delete"),
    }).pipe(Effect.asVoid),

  deleteByUser: (userId) =>
    Effect.tryPromise({
      try: () => db.execute("DELETE FROM identifiers WHERE user_id = ?", [userId]),
      catch: infra("identifier.deleteByUser"),
    }).pipe(Effect.asVoid),
};

// ---------------------------------------------------------------------------
// Wire it up — the canonical pattern for every store in the library.
// ---------------------------------------------------------------------------

const storesLayer = Layer.mergeAll(
  Layer.succeed(Auth.SessionStore)(sessionStore),
  Layer.succeed(Auth.UserStore)(userStore),
  Layer.succeed(Auth.IdentifierStore)(identifierStore),
);
```

Provide `storesLayer` underneath `Auth.SessionService.layer(config)` and whichever sign-in feature's own store (`Auth.Email.EmailPasswordStore`, `Auth.PhoneOtpStore` + `Auth.PhoneOtpUserStore`, …) the same way — one `Layer.succeed(Auth.XStore)(impl)` per contract, merged together.

## 4. What "implement only what you use" means in practice

A store contract's methods correspond 1:1 to what the feature that owns it needs — there's no unused surface to stub out. If your app never enables WebAuthn, you never implement `ChallengeStore`/`CredentialStore`; if you don't mount the OIDC provider, `OidcClientStore`/`OidcCodeStore`/`OidcTokenStore`/ `OidcConsentStore` don't exist for you. A handful of methods are themselves optional on the interface (`OAuthAccountStore.hasPassword`, `OAuthUserStore.updateUser`, `OidcTokenStore.listByFamily`) — each is documented at the call site with what's skipped when it's absent.

## 5. Every store contract in core

Grouped by cluster, in the same order the source is organized. "Namespace" is how you reach it from `import * as Auth from "@thomasfosterau/effect-auth"` (a bare name is exported at the package root); "Powers" names the service that consumes it.

**Session & identity (core spine)**

| Contract             | Namespace                 | What it holds                                                    | Powers                                                                                                        |
| -------------------- | ------------------------- | ---------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------- |
| `SessionStore`       | `Auth.SessionStore`       | Sessions keyed by the SHA-256 hash of the bearer token           | `SessionService` — every sign-in flow                                                                         |
| `UserStore`          | `Auth.UserStore`          | Read a user by id                                                | Read path used across the library                                                                             |
| `UserServiceStore`   | `Auth.UserServiceStore`   | Get/update/delete the user record (name, image, attributes)      | `UserService` — profile updates, account deletion                                                             |
| `IdentifierStore`    | `Auth.IdentifierStore`    | Email/username/phone claims, globally unique per `(type, value)` | Identifier epic — EmailPassword, Username, PhoneOtp, MagicLink, EmailOtp, OAuth linking, SSO, Admin, and more |
| `TrustedDeviceStore` | `Auth.TrustedDeviceStore` | Trusted-device cookie tokens, keyed by their hash                | `TrustedDeviceService` — "remember this device" 2FA skip                                                      |

**Password & recovery**

| Contract                 | Namespace                              | What it holds                              | Powers                                   |
| ------------------------ | -------------------------------------- | ------------------------------------------ | ---------------------------------------- |
| `EmailPasswordStore`     | `Auth.Email.EmailPasswordStore`        | Create a user; get/set the password hash   | `EmailPasswordService` — sign-up/sign-in |
| `EmailVerificationStore` | `Auth.Email.EmailVerificationStore`    | Email-verification tokens                  | `EmailVerificationService`               |
| `PasswordResetStore`     | `Auth.Password.PasswordResetStore`     | Password-reset tokens                      | `PasswordResetService`                   |
| `PasswordResetUserStore` | `Auth.Password.PasswordResetUserStore` | Set the password hash on a completed reset | `PasswordResetService`                   |

**Passwordless sign-in**

| Contract             | Namespace                      | What it holds                                     | Powers                                                 |
| -------------------- | ------------------------------ | ------------------------------------------------- | ------------------------------------------------------ |
| `MagicLinkStore`     | `Auth.MagicLinkStore`          | Magic-link tokens, by token and by email          | `MagicLinkService`                                     |
| `MagicLinkUserStore` | `Auth.MagicLinkUserStore`      | Create a user on first magic-link sign-in         | `MagicLinkService`                                     |
| `EmailOtpStore`      | `Auth.Email.EmailOtpStore`     | One active email OTP per `(email, purpose)`       | `EmailOtpService`                                      |
| `EmailOtpUserStore`  | `Auth.Email.EmailOtpUserStore` | Create a user on first email-OTP sign-in          | `EmailOtpService`                                      |
| `PhoneOtpStore`      | `Auth.PhoneOtpStore`           | One active phone OTP per `(phoneNumber, purpose)` | `PhoneOtpService`                                      |
| `PhoneOtpUserStore`  | `Auth.PhoneOtpUserStore`       | Create a user on first phone-OTP sign-in          | `PhoneOtpService`                                      |
| `OneTimeTokenStore`  | `Auth.OneTimeTokenStore`       | Generic one-time tokens                           | `OneTimeTokenService` / `redeemOneTimeTokenForSession` |

**Second factor**

| Contract                  | Namespace                                  | What it holds                                            | Powers                                             |
| ------------------------- | ------------------------------------------ | -------------------------------------------------------- | -------------------------------------------------- |
| `MultiFactorStore`        | `Auth.MultiFactor.MultiFactorStore`        | TOTP secret + backup codes per user                      | `MultiFactorService` — 2FA enrollment/verification |
| `PendingMultiFactorStore` | `Auth.MultiFactor.PendingMultiFactorStore` | Short-lived "password OK, awaiting 2FA" challenge tokens | `MultiFactorService` sign-in step                  |
| `OtpSecondFactorStore`    | `Auth.MultiFactor.OtpSecondFactorStore`    | Pending email/SMS-OTP-as-second-factor records           | `OtpSecondFactorService`                           |
| `ChallengeStore`          | `Auth.MultiFactor.ChallengeStore`          | WebAuthn ceremony challenges                             | `WebAuthnService`                                  |
| `CredentialStore`         | `Auth.MultiFactor.CredentialStore`         | WebAuthn public-key credentials                          | `WebAuthnService`                                  |

**OAuth & SSO**

| Contract                 | Namespace                      | What it holds                                               | Powers                                           |
| ------------------------ | ------------------------------ | ----------------------------------------------------------- | ------------------------------------------------ |
| `OAuthStateStore`        | `Auth.OAuth.OAuthStateStore`   | CSRF state for the OAuth redirect round trip                | `OAuthService`                                   |
| `OAuthAccountStore`      | `Auth.OAuth.OAuthAccountStore` | Linked provider accounts                                    | `OAuthService` — social login, linking/unlinking |
| `OAuthUserStore`         | `Auth.OAuth.OAuthUserStore`    | Create/get/optionally update a user from a provider profile | `OAuthService`                                   |
| `GoogleOneTapNonceStore` | `Auth.GoogleOneTapNonceStore`  | One Tap replay-protection nonces                            | `GoogleOneTapService`                            |
| `SsoProviderStore`       | `Auth.SsoProviderStore`        | Registered OIDC/SAML SSO connections                        | `SsoService` — enterprise SSO                    |
| `SamlReplayStore`        | `Auth.SamlReplayStore`         | One-time consume of AuthnRequest/assertion ids              | SAML SP replay protection (`packages/saml`)      |

**OIDC provider**

| Contract           | Namespace               | What it holds                                                          | Powers                |
| ------------------ | ----------------------- | ---------------------------------------------------------------------- | --------------------- |
| `OidcClientStore`  | `Auth.OidcClientStore`  | Registered OIDC clients — static and dynamically registered (RFC 7591) | `OidcProviderService` |
| `OidcCodeStore`    | `Auth.OidcCodeStore`    | Authorization codes and pending-consent artifacts                      | `OidcProviderService` |
| `OidcTokenStore`   | `Auth.OidcTokenStore`   | Issued access/refresh tokens, refresh-family metadata                  | `OidcProviderService` |
| `OidcConsentStore` | `Auth.OidcConsentStore` | Recorded user consent per client                                       | `OidcProviderService` |

**API keys, devices, admin, orgs**

| Contract                   | Namespace                       | What it holds                                                         | Powers                                             |
| -------------------------- | ------------------------------- | --------------------------------------------------------------------- | -------------------------------------------------- |
| `ApiKeyStore`              | `Auth.ApiKeyStore`              | Hashed API keys                                                       | `ApiKeyService`                                    |
| `JwtKeyStore`              | `Auth.JwtKeyStore`              | JWT signing key pairs                                                 | `JwtService` / JWKS                                |
| `DeviceAuthorizationStore` | `Auth.DeviceAuthorizationStore` | RFC 8628 `device_code`/`user_code` records                            | `DeviceAuthorizationService`                       |
| `AnonymousUserStore`       | `Auth.AnonymousUserStore`       | Create/delete guest users                                             | `AnonymousService`                                 |
| `AdminUserStore`           | `Auth.AdminUserStore`           | List/create users, admin password reset                               | `AdminService`                                     |
| `OrganizationStore`        | `Auth.OrganizationStore`        | Organizations, members, invitations, teams, custom roles              | `OrganizationService`                              |
| `OrganizationDomainStore`  | `Auth.OrganizationDomainStore`  | Email-domain claims and their verification state (unique on `domain`) | `OrganizationService` — domains + JIT provisioning |
| `AccountManagementStore`   | `Auth.AccountManagementStore`   | Pending email-change/delete-account tokens                            | `AccountManagementService`                         |

**Rate limiting, lockout, authorization**

| Contract              | Namespace                          | What it holds                                                       | Powers                                                                                 |
| --------------------- | ---------------------------------- | ------------------------------------------------------------------- | -------------------------------------------------------------------------------------- |
| `RateLimitStore`      | `Auth.RateLimitStore`              | Rate-limit counters                                                 | `RateLimiter`                                                                          |
| `AccountLockoutStore` | `Auth.Plugins.AccountLockoutStore` | Atomic lockout counters (see §2)                                    | `AccountLockoutPlugin`                                                                 |
| `PolicyStore`         | `Auth.PolicyStore.PolicyStore`     | Versioned policy documents, templates, and template-linked policies | Policies-as-data — the M3 authorization framework, organization dynamic access control |

That's 42 store contracts. None are required — only implement the ones behind the features you actually enable.

## 6. Reference implementations

Prefer one of these over writing your own when it fits your stack:

- **[`packages/sql`](../../packages/sql)** — driver-agnostic over `effect/sql` (for SQLite, Cloudflare D1 and PostgreSQL; MySQL is not supported, so MySQL users take `packages/drizzle`'s MySQL tables, which cover three stores only). Implements 22 of the 43 contracts — the whole credential/session/OAuth/WebAuthn/MFA/passwordless/lockout core. Not yet covered: `OneTimeTokenStore`, `TrustedDeviceStore`, `PhoneOtp*Store`, `OrganizationStore`, `OrganizationDomainStore`, `AdminUserStore`, `ApiKeyStore`, the OIDC provider stores, `SsoProviderStore`, `SamlReplayStore`, `DeviceAuthorizationStore`, `GoogleOneTapNonceStore`, `JwtKeyStore`, `OtpSecondFactorStore`, `AnonymousUserStore`, `AccountManagementStore`, and `PolicyStore` — bring your own or use the `KeyValueStore` defaults for those until they land. `Stores.ts`'s module doc comment is the authoritative source for the atomicity guarantees (`ON CONFLICT ... DO UPDATE` / `UPDATE ... RETURNING` for single-row upserts and counters; `sql.withTransaction` for multi-step writes) — read it before copying the patterns into your own store.
- **[`packages/alchemy`](../../packages/alchemy)** — the same store coverage as `packages/sql`, over Cloudflare D1 via Alchemy v2, plus the `AuthSchema` infrastructure resource that reconciles the D1 schema on every deploy. Good default if you're already on D1/Alchemy; same "not yet covered" list as above.
- **[`packages/drizzle`](../../packages/drizzle)** — `SessionStore` + `UserStore` + `IdentifierStore` only, over `drizzle-orm` with PostgreSQL, SQLite, and MySQL table sets (native `jsonb`/`timestamptz` on Postgres, per-dialect mappings elsewhere) instead of `packages/sql`'s TEXT/epoch-ms codecs. Stands alone (doesn't wrap `packages/sql`) — reach for it when your app already models its schema in Drizzle and you want the auth tables in the same migration pipeline; reach for `packages/sql` instead when you need the other 40 contracts too.
- **[`KeyValueStores.ts`](../../packages/effect-auth/src/KeyValueStores.ts)** — `KeyValueStore`-backed (from `effect/persistence`) defaults for the ephemeral/token-shaped stores: OAuth state, WebAuthn challenges, rate limits, verification/reset/magic-link tokens, email OTPs, pending multi-factor challenges, and Google One Tap nonces. A natural fit for Redis, Cloudflare KV, or an in-memory map — provide any `KeyValueStore` backend (`KeyValueStore.layerMemory`, `KeyValueStore.layerFileSystem`, `KeyValueStore.layerSql`, …) underneath. Its module doc documents a deliberate read-modify-write shortcut on `RateLimitStore.increment`/`EmailOtpStore.incrementAttempts` — fine for best-effort limiting, not for the §2 MUST-be-atomic tier.
