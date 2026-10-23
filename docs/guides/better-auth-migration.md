# Migrating from Better Auth

This guide is for an application that already runs on [Better Auth](https://www.better-auth.com/) and wants to move to effect-auth. It maps Better Auth's concepts onto effect-auth's, walks each auth flow, covers the browser client, gives concrete guidance for moving the data, and ends with an honest list of what effect-auth does not do or deliberately does differently.

Everything claimed here about effect-auth is taken from the tree: `packages/effect-auth/src/index.ts` is the public surface, `packages/effect-auth/src/http/HttpApi.ts` is the HTTP contract, and `packages/sql/src/Schema.ts` is the reference schema.

## 1. The shape of the change

Better Auth is a **framework instance**: `betterAuth({ ... })` returns an object that owns your database connection, your route handler, and a server-side API, and `plugins: [...]` bolts features onto that instance. effect-auth is a **headless core with optional tiers around it** (see [ADR 0017](../adr/0017-batteries-included-auth-framework.md)): every feature is an Effect `Context.Service` you provide with a `Layer`, and the HTTP surface — like the typed client, the framework bindings and the protocol servers — is one optional projection of those services rather than the thing they live inside.

The practical consequences are worth internalising before you start:

- There is no `auth` object and no `auth.api.*`. You get services from context (`yield* Auth.SessionService`) and compose them with `Layer.mergeAll` / `Layer.provide`.
- There is no adapter for your ORM. Features depend on small store contracts (`SessionStore`, `UserStore`, `IdentifierStore`, …) that you either implement yourself or take from `@thomasfosterau/effect-auth-sql` / `-drizzle` / `-alchemy`.
- A feature is "enabled" exactly when its layer is in the context. Optional HTTP routes answer `404` until the service behind them is provided — that is the whole configuration mechanism.
- Errors are values in the typed error channel, not thrown exceptions; every service method has `R = never` once its layer is built.
- There is no CLI. No `@better-auth/cli generate`, no `migrate` command that inspects your config. `@thomasfosterau/effect-auth-sql` ships a fixed DDL list (`schemaStatements`) and a `migrate` effect; everything else is your migration pipeline's job.

## 2. Concept map

| Better Auth                                      | effect-auth                                                                                                           |
| ------------------------------------------------ | --------------------------------------------------------------------------------------------------------------------- |
| `betterAuth({ ... })` instance                   | a `Layer` composed from per-service `X.layer(config)` calls                                                           |
| `plugins: [twoFactor(), organization(), …]`      | merging `MultiFactorService.layer(…)`, `OrganizationService.layer(…)`, … into that layer                              |
| `database: drizzleAdapter(db, …)`                | store contracts + one of `@thomasfosterau/effect-auth-sql`, `-drizzle`, `-alchemy`, or your own                       |
| `auth.handler` (mounted at `/api/auth/*`)        | `(await Auth.Http.makeAsync({ services, prefix: "/api/auth" })).handler` — a plain `(Request) => Promise<Response>`   |
| `auth.api.getSession({ headers })`               | `yield* sessions.validateSession(id)` on `Auth.SessionService`, or `GET /session` over HTTP                           |
| `emailAndPassword: { enabled: true }`            | `Auth.Email.EmailPasswordService.layer(config)` (+ `Auth.AuthLifecycleService` for the sign-up/sign-in orchestration) |
| `socialProviders: { github: { … } }`             | `Auth.OAuth.OAuthService.layer({ github: Auth.OAuth.GitHubProvider({ … }) })`                                         |
| `sendVerificationEmail` / `sendResetPassword` …  | per-feature callbacks, or derive all of them from one `EmailSender` with `Auth.emailCallbacks(sender, identifiers)`   |
| `secret` (signing key)                           | per-feature secrets: `Cipher` keys, `SessionCacheConfig` HMAC key, `JwtKeyStore` keys — no single global secret       |
| `session.cookieCache`                            | `cookie: { cache: { … } }` on `Auth.Http.makeAsync` (`SessionCookieCache.ts`)                                         |
| `advanced.crossSubDomainCookies` / trusted hosts | `trustedOrigins` + `trustedProxy` options on `Auth.Http.makeAsync`                                                    |
| `createAuthClient` from `better-auth/client`     | `createAuthClient` from `@thomasfosterau/effect-auth-client`                                                          |
| `better-auth/react` \| `/svelte` \| `/vue`       | `@thomasfosterau/effect-auth-react` \| `-svelte` \| `-vue` \| `-solid`                                                |

### Config → layers, concretely

A minimal Better Auth instance with email+password and GitHub becomes a layer graph. Each service asks for its stores; you provide them once, and `Auth.Http.makeAsync` takes the whole thing as `services`:

```ts
import { Layer } from "effect";
import * as Auth from "@thomasfosterau/effect-auth";
import * as Sql from "@thomasfosterau/effect-auth-sql";

const stores = Sql.layer.pipe(Layer.provide(SqlClientLayer));

const services = Layer.mergeAll(
  Auth.SessionService.layer({
    sessionExpiresIn: { activePeriod: 30 * 864e5, idlePeriod: 14 * 864e5 },
  }),
  Auth.AuthLifecycleService.layer(),
  Auth.Email.EmailPasswordService.layer(),
  Auth.Password.PasswordHasher.layer(),
  Auth.UserService.layer(),
  Auth.Hooks.Default,
).pipe(Layer.provideMerge(stores));

const { handler } = await Auth.Http.makeAsync({
  services,
  prefix: "/api/auth",
  trustedOrigins: ["https://app.example.com"],
});
```

`Auth.Http.makeAsync` resolves to `{ handler, dispose }`. `handler` is a standard Web `Request => Promise<Response>`, so it mounts anywhere Better Auth's handler did (Next.js route handlers, Hono, Elysia, Bun/Deno/Workers `fetch`) with the same catch-all path.

`services` connects to the database while it builds, so the example uses `Auth.Http.makeAsync`, which waits for that build. It resolves to the same `{ handler, dispose }` once `services` is built and checked, and rejects with the startup errors (a missing `RateLimiter`, for example), so the app fails to start. `Auth.Http.make` is the synchronous form: it throws those errors only for a build that finishes before it returns. With an asynchronous build like this one it cannot, and every request would reject with them instead.

The set of services `Auth.Http.makeAsync` requires is `AuthServices` in `http/HttpServer.ts`: `AuthLifecycleService`, `SessionService`, `EmailPasswordService`, `IdentifierStore`, `PasswordHasher`, `EmailVerificationService`, `PasswordResetService`, `UserService`, `Hooks`. Everything else — magic link, OTP, multi-factor, organizations, admin, API keys, SSO, the OIDC provider, SCIM — is resolved optionally per handler, which is why those routes return `404` until you merge the corresponding layer in.

### Plugins vs hooks

Better Auth's `plugins` array does two different jobs: it adds features, and it adds cross-cutting behaviour (`hooks.before` / `hooks.after`). In effect-auth those are separate mechanisms. Features are layers. Cross-cutting behaviour is the `Hooks` service (`src/Hooks.ts`) with first-party plugins under `src/plugins/` — `AccountLockoutPlugin`, `AuditPlugin`, `CaptchaPlugin`, `IPRateLimitPlugin`, `LastLoginMethodPlugin`, `NormalizeEmailPlugin` and `RateLimitPlugin`, plus `BannedUserPlugin` from `Admin.ts` and `ScimDeactivatedPlugin` from `Scim.ts`. Register them where you would have provided `Auth.Hooks.Default`.

## 3. Storage: adapters → store contracts

Better Auth owns your tables through an adapter and generates the schema for you. effect-auth inverts this: it declares ~42 store contracts and never touches a driver. Three routes exist, and you can mix them:

- **`@thomasfosterau/effect-auth-sql`** — driver-agnostic over `effect/sql` (SQLite, Cloudflare D1 and PostgreSQL; MySQL is not supported, see the drizzle route below). `Sql.layer` provides the implemented stores; `Sql.migrate` runs `Sql.schemaStatements`, all of them `CREATE TABLE IF NOT EXISTS`, so it is safe on every deploy. This is the closest analogue to a Better Auth adapter and the fastest path off it.
- **`@thomasfosterau/effect-auth-drizzle`** — for apps that already model their schema in Drizzle and want the auth tables inside the existing migration pipeline. It covers the three stores every credential sign-in touches (`SessionStore`, `UserStore`, `IdentifierStore`) on PostgreSQL, SQLite, or MySQL; see that package's README for its exact tables.
- **Bring your own** — implement `typeof Auth.XStore.Service` over whatever client you have. [`byo-stores.md`](./byo-stores.md) is the reference, including which methods **must** be atomic.

Two invariants differ from Better Auth and matter for both wiring and data migration:

- **Bearer secrets are stored hashed.** Session ids, magic-link / verification / reset / one-time tokens, API keys and OIDC codes reach a store as the unsalted SHA-256 hex digest produced by `hashToken` (`src/TokenHash.ts`). Stores index on the digest; the raw secret exists only in transit.
- **Timestamps are epoch-millisecond `BIGINT` in `packages/sql`,** because epoch-ms overflows Postgres `int4` and MySQL signed `INT`. At the store boundary the domain records still use real `Date` objects.

## 4. Flow-by-flow equivalents

Names below are the exact exports; `Auth` is `import * as Auth from "@thomasfosterau/effect-auth"`.

### Email + password

`Auth.Email.EmailPasswordService` (`signUp`, `signIn`, `changePassword`, `setPassword`) over `EmailPasswordStore`, with `Auth.Password.PasswordHasher` doing the hashing and `Auth.AuthLifecycleService` (`signUp`, `signIn`, `verifyEmail`) orchestrating the sign-up → verification → session path that Better Auth hides inside its instance. Verification and reset are their own services — `Auth.Email.EmailVerificationService` and `Auth.Password.PasswordResetService` — reached over `POST /sign-up`, `POST /sign-in`, `POST /email-verification/send|verify`, `POST /password-reset/request|reset`, `POST /change-password`.

The default hasher is PBKDF2-SHA256; Argon2id lives in `@thomasfosterau/effect-auth-argon2` as a drop-in `PasswordHasher`. Better Auth hashes with scrypt by default, so **existing password hashes do not verify** — see §6.

### Social OAuth

`Auth.OAuth.OAuthService` (`generateAuthorizationUrl`, `handleCallback`, `signInWithCallback`, `linkAccount`, `unlinkAccount`, `refreshAccessToken`) with providers built from the exported constructors: `GoogleProvider`, `GitHubProvider`, `DiscordProvider`, `MicrosoftProvider`, `AppleProvider`, `FacebookProvider`, `TwitterProvider`, `LinkedInProvider`, `TwitchProvider`, `SpotifyProvider`, `GitLabProvider`, `RedditProvider`, `DropboxProvider`, `NotionProvider`, `SlackProvider`, `ZoomProvider`, `TikTokProvider`, `RobloxProvider`, `KickProvider`, `HuggingFaceProvider`, or `Auth.OAuth.provider(...)` for anything else. Stores: `OAuthStateStore`, `OAuthAccountStore`, `OAuthUserStore`.

**This is the one flow with no HTTP endpoints.** Better Auth gives you `/sign-in/social` and `/callback/:provider`; effect-auth's contract has neither, so you mount two routes of your own that call `generateAuthorizationUrl` and `signInWithCallback` and set the session cookie. Budget for that.

### Magic link

`Auth.MagicLinkService` (`send`, `verify`) over `MagicLinkStore` + `MagicLinkUserStore`, on `POST /magic-link/send` and `POST /magic-link/verify`. Delivery is the `sendMagicLink` callback in `MagicLinkConfig`.

### Email OTP and phone OTP

`Auth.Email.EmailOtpService` (`send`, `signIn`, `check`) on `POST /email-otp/send` and `POST /sign-in/email-otp`, and `Auth.PhoneOtpService` on `POST /phone-otp/send` and `POST /sign-in/phone-otp`. Both hash the code at rest, scope it by purpose, and limit attempts. Better Auth's `emailOtp` and `phoneNumber` plugins map here one for one.

### Passkeys / WebAuthn

`Auth.MultiFactor.WebAuthnService` (`generateRegistrationChallenge`, `verifyRegistration`, `generateAuthenticationChallenge`, `verifyAuthentication`, `listCredentials`, `deleteCredential`, `renameCredential`) over `ChallengeStore` + `CredentialStore`. The CBOR / COSE / `clientDataJSON` parsing is in-repo (`multifactor/WebAuthnCodec.ts`) — no `@simplewebauthn` dependency.

**Also service-only**: there are no passkey endpoints on the HTTP contract and no passkey methods on the browser client, so the four routes Better Auth's `passkey` plugin exposes are yours to write.

### Two-factor

`Auth.MultiFactor.MultiFactorService` (`enable`, `confirmEnable`, `disable`, `isEnabled`, `beginChallenge`, `verifyTotp`, `verifyBackupCode`, `regenerateBackupCodes`) over `MultiFactorStore` + `PendingMultiFactorStore`, on `POST /multi-factor/enable|confirm|disable|verify-totp|verify-backup-code|regenerate-backup-codes`. TOTP/HOTP primitives are in `Auth.MultiFactor` (`generateTotp`, `verifyTotp`, `generateHotp`, `verifyHotp`, `generateOtpUri`).

Password sign-in integrates through the `SecondFactorGate` seam: provide `MultiFactorGateLayer` (or `OtpSecondFactorGateLayer` for emailed/texted codes, or `TrustedDeviceWithMultiFactorGateLayer` / `TrustedDeviceWithOtpSecondFactorGateLayer` to honour remembered devices) and `signIn` returns a challenge instead of a session until the second factor clears. That replaces Better Auth's `twoFactor()` plugin plus its `trustDevice` option.

### Organizations and teams

`Auth.OrganizationService` covers organizations, members, invitations, teams and per-organization roles: `createOrganization`, `updateOrganization`, `deleteOrganization`, `getFullOrganization`, `listOrganizations`, `inviteMember`, `acceptInvitation`, `rejectInvitation`, `cancelInvitation`, `listInvitations`, `listUserInvitations`, `addMember`, `removeMember`, `updateMemberRole`, `createTeam`, `updateTeam`, `deleteTeam`, `addTeamMember`, `removeTeamMember`, `listTeams`, `listTeamMembers`, `listTeamsForMember`, `upsertOrgRole`, `deleteOrgRole`, `listOrgRoles`, `checkPermission`, `requirePermission`. Teams are hierarchical ([ADR 0016](../adr/0016-hierarchical-teams.md)) and roles are data, not a compile-time union ([ADR 0009](../adr/0009-organization-data-model-and-permissions.md)). The HTTP surface is `/organization/*`, `/organizations`, `/teams/*` and `/invitations/*`.

### Admin

`Auth.AdminService` (`listUsers`, `setRole`, `banUser`, `unbanUser`, `removeUser`, `revokeUserSessions`, `impersonateUser`, `createUser`, `setUserPassword`, `listUserSessions`) over `AdminUserStore`, on `/admin/*`. Pair it with `BannedUserPlugin` so a ban takes effect on the next request rather than at session expiry.

### API keys

`Auth.ApiKeyService` (`create`, `verify`, `verifyWithRateLimit`, `get`, `list`, `update`, `delete`, `deleteAllExpired`) over `ApiKeyStore`, on `/api-keys*`. Keys are stored as digests only and carry permissions plus time-based quota refill ([ADR 0012](../adr/0012-api-key-design.md)).

### Enterprise SSO (as a relying party) and the OIDC provider

Two separate features, as in Better Auth:

- **`Auth.SsoService`** signs your users in _through_ someone else's IdP: `registerProvider`, `registerSamlProvider`, `resolveProviderForEmail`, `signIn`, `handleCallback`, `handleSamlCallback`, `samlMetadata`, on `POST /sso/register`, `POST /sign-in/sso`, `POST /sso/callback`, `POST /sso/saml/acs/:providerId`, `GET /sso/saml/metadata/:providerId`. OIDC providers work out of core; SAML additionally needs `SamlVerifier` + `SamlReplayStore`, implemented by `@thomasfosterau/effect-auth-saml`.
- **`Auth.OidcProviderService`** makes _you_ the IdP: `registerClient`, `authorize`, `consent`, `token`, `userinfo`, `getMetadata`, RFC 7591/7592 dynamic client registration, on `/oauth2/*`, `/register*`, `/.well-known/openid-configuration` and `/.well-known/jwks.json`. `Auth.mcpProviderPreset` is a ready-made config for an MCP-facing auth server; see [`mcp-provider.md`](./mcp-provider.md).

SCIM provisioning (`Auth.ScimService`) has no Better Auth counterpart; [`scim.md`](./scim.md) covers it.

### Delivery of email and SMS

Better Auth takes a `sendX` callback per feature. effect-auth does too, but adds a single seam so you write the transport once: implement `Auth.EmailSender` / `Auth.SmsSender` and derive every per-feature callback with `Auth.emailCallbacks(sender, identifiers)` and `Auth.smsCallbacks(sender, identifiers)`. `@thomasfosterau/effect-auth-resend` and `@thomasfosterau/effect-auth-twilio` are ready-made senders.

Better Auth leaves it to the app to schedule a send outside the response (the `waitUntil` workaround). effect-auth does that itself for the flows that hide whether an account exists: they hand the send to `Auth.DeliveryScheduler`, and on Workers you provide `Auth.DeliveryScheduler.waitUntil(...)` per request. Every other send is awaited. The core README's "Delivery" section lists which flow does which.

## 5. Client migration

`better-auth/client` → `@thomasfosterau/effect-auth-client`. Both export `createAuthClient`; both send credentialed `fetch` requests at a base URL and keep an observable session store. The differences that matter:

- **No client plugins to mirror.** Better Auth requires the client plugin list to match the server's. The effect-auth client exposes every endpoint a browser would call up front — `signUp`, `signIn`, `signOut`, `getSession`, `identifiers`, `magicLink`, `emailOtp`, `phoneOtp`, `multiFactor`, `organization`, `apiKeys`, `admin`, `sso`, `oidc`, `device`, `googleOneTap`, `multiSession`, `changeEmail`, `deleteUser` — and endpoints whose server layer is absent simply reject with `404`. `extend()` is there for your own additions.
- **Framework bindings are separate packages**, not subpath imports: `@thomasfosterau/effect-auth-react`, `-svelte`, `-vue`, `-solid`, each built on the vanilla client with out-of-the-box form components (`SignInForm`, `SignUpForm`, password reset, magic link, email OTP).
- **Types come from the server package's `Http` namespace** (`Auth.Http.SessionWithUserView`, `Auth.Http.SignUpPayload`, …) and erase at compile time, so nothing server-side reaches the bundle.
- **Errors reject with `AuthClientError`** carrying the HTTP `status` and the server's message — no `{ data, error }` tuple.
- **Trusted origins are mandatory for cross-origin deployments.** Every call sends `credentials: "include"`, and the server rejects state-changing cross-origin requests whose `Origin` is not in `trustedOrigins`.

[`client.md`](./client.md) is the full client guide.

## 6. Moving the data

Better Auth's core schema is four tables — `user`, `session`, `account`, `verification` — plus one per plugin. effect-auth's reference schema is `packages/sql/src/Schema.ts`, `auth_`-prefixed so it can sit beside your application tables. Migrate table by table.

### `user` → `auth_users` + `auth_identifiers`

This is the one structural change you cannot skip. effect-auth's `User` is **surrogate-keyed**: it has `id`, `name`, `image`, `password_hash`, `attributes`, `created_at`, `updated_at` and _no email column_ ([ADR 0002](../adr/0002-unified-data-model.md), DESIGN §D12). Every handle — email, username, phone — is a row in `auth_identifiers`, unique on `(type, value)`:

```sql
-- 1. the user row (note: no email, no email_verified)
INSERT INTO auth_users (id, name, image, password_hash, attributes, created_at, updated_at)
SELECT u.id, u.name, u.image, NULL, '{}', ..., ...
FROM "user" u;

-- 2. Better Auth's user.email becomes an email Identifier row
INSERT INTO auth_identifiers (id, user_id, type, value, verified, verified_at, created_at)
SELECT <new uuid>, u.id, 'email', lower(trim(u.email)), u."emailVerified", ..., ...
FROM "user" u;
```

Three rules the store enforces, so get them right in the migration: `value` is stored **normalized** (emails and usernames trimmed and lowercased, phones in E.164 — the store does not normalize for you); `(type, value)` must be backed by a **real unique index**, because `claimIdentifier`'s race repair depends on a concurrent duplicate `create` genuinely failing; and `verified` carries the verification state that used to live on `user.emailVerified`, with `verified_at` as its timestamp.

If you used Better Auth's `username` plugin, its `user.username` becomes a second identifier row with `type = 'username'`. Same for `phoneNumber`, with `type = 'phone'`.

Anything else you kept on the Better Auth user row through `additionalFields` goes into the `attributes` JSON bag.

### `account` → `auth_users.password_hash` + `auth_oauth_accounts`

Better Auth stores both credentials and social links in one `account` table, discriminated by `providerId`. effect-auth splits them:

- Rows with `providerId = 'credential'`: the password belongs on `auth_users.password_hash`. **Whether the hash string carries over depends on the algorithm you hashed with.** Argon2id hashes carry over as they are: copy the PHC string into the column and provide `@thomasfosterau/effect-auth-argon2`, whose `verify` parses the cost parameters, salt and digest length out of the _stored_ hash rather than assuming its configured ones — so hashes written by another Argon2 implementation, or under older parameters, keep verifying with no forced re-hash. A hash effect-auth has no verifier for — Better Auth's default scrypt, against a core that defaults to PBKDF2-SHA256 — does not: either force a password reset for credential users, or keep the Better Auth verifier alive behind a custom `PasswordHasher` implementation and re-hash on next successful sign-in ([ADR 0006](../adr/0006-credential-verification-typology.md) covers the verification typology).
- Social rows: into `auth_oauth_accounts` (`user_id`, `provider`, `provider_id`, `email`, `name`, `picture`, `access_token`, `refresh_token`, `expires_at`), unique on `(provider, provider_id)`. Better Auth's `accountId` is `provider_id`; its `providerId` is `provider`. `idToken` and `scope` have no column — drop them or park them in your own table.

### `session` → `auth_sessions`

Columns map cleanly (`id`, `user_id`, `expires_at`, `created_at`, `last_activity_at`, `attributes`) with one critical difference: **`auth_sessions.id` is the SHA-256 hex digest of the session token, not the token itself** ([ADR 0004](../adr/0004-hashed-tokens-at-rest.md)). Better Auth's `session.token` is the raw value, so a row-for-row copy would make every session unusable.

The recommended path is not to migrate sessions at all: let them lapse, and have users sign in again on the cut-over. Carrying them is possible — `hashToken` is unsalted SHA-256, so `auth_sessions.id = sha256(session.token)` reproduces the right key, and effect-auth's cookie value is the raw token — but you would also have to re-issue the cookie under the new name (`conduit_session` by default, `__Host-` prefixed when `secure`) with the signature stripped off Better Auth's cookie value. The forced re-authentication is almost always the better trade.

Better Auth's `ipAddress` / `userAgent` columns have no first-class equivalent; put them in `attributes` if you want them.

### `verification` → nothing

Better Auth's generic `verification` table backs email verification, password reset, OTPs and more. effect-auth uses purpose-specific tables — `auth_email_verifications`, `auth_password_resets`, `auth_magic_links`, `auth_email_otps` — and stores the token as its digest. These rows are short-lived by construction, so **do not migrate them**: let outstanding links and codes expire, and tell users to request a new one after the cut-over.

### Plugin tables

`twoFactor` → `auth_multi_factor` (`user_id`, `secret`, `backup_codes`, `verified`, `last_used_counter`) plus `auth_pending_multi_factor` for in-flight challenges. TOTP secrets are portable, so this table _can_ be carried over; back-up codes are hashed. `passkey` → `auth_webauthn_credentials` (+ `auth_webauthn_challenges`). `organization` → the organization stores. Rate limits → `auth_rate_limits`; lockout counters → `auth_account_lockouts`. Run `Sql.migrate` first so every target table and index exists, then backfill.

### Suggested order

1. Stand up the new schema (`Sql.migrate`, or your own DDL) alongside the running Better Auth database.
2. Backfill `auth_users` → `auth_identifiers` → `auth_oauth_accounts` → plugin tables, in that order (identifiers depend on users; everything depends on both).
3. Wire the layers and mount `Auth.Http.makeAsync` at the same prefix Better Auth used, so client paths that survive (`/sign-in`, `/sign-up`, `/sign-out`, `/session`) keep working.
4. Write the routes with no contract equivalent: social OAuth start/callback, and passkeys if you use them.
5. Swap the browser client, then cut over and accept the forced re-authentication.

## 7. SvelteKit on Workers, with auth in its own Worker

This section covers one deployment shape in particular: a SvelteKit app on Cloudflare Workers, with
Better Auth in its own internal Worker that the app reaches over a service binding.

### The split-service topology

The topology carries over unchanged, and the library owns its two seams:

- **Session resolution over the binding.** `Http.RemoteSession` resolves the session, with the
  cookieless skip and an explicit fail-open or fail-closed choice.
- **The `Set-Cookie` relay.** Covered in [Auth as a separate service](split-auth-service.md).

Three points carry over from the Better Auth setup:

- The app's public origin must be in the auth Worker's `trustedOrigins`, because the browser's
  `Origin` arrives through a server-to-server call.
- The auth Worker stays internal only if `workers.dev` is turned off explicitly. An un-routed
  Worker is still a published Worker.
- effect-auth's handler serves more than Better Auth's (API keys, admin, SCIM, and the OIDC
  provider when configured), so exposing it by mistake costs more.

On the SvelteKit side, [`@thomasfosterau/effect-auth-sveltekit`](../../packages/sveltekit/README.md)
replaces the hand-written `hooks.server.ts` and form-action glue. Its `handle` resolves the session
before `load` and sets `Cache-Control` after authentication, so a page rendered for a signed-in
viewer is never cached for an anonymous one. Its `credentialAction` relays `Set-Cookie`, validates
the redirect target with `safeRedirect`, and reports `401` and `429` as distinct failures (a
throttled sign-in no longer reads as "the form did nothing").

### Cookie-name cutover

Better Auth's session cookie is `better-auth.session_token`, or
`__Secure-better-auth.session_token` over HTTPS. effect-auth's is computed by
`SessionCookies.cookieNames`: `conduit_session` by default, with a `__Host-` prefix when the cookie
is `Secure` and its path is `/`. The two names never coincide, and Better Auth's session rows don't
carry over (§6), so **every session ends at the switch**. You have two options:

- **Accept a forced re-login.** Deploy, and every signed-in browser becomes anonymous. This is the
  simple option, and the right one unless the re-login itself is a problem.
- **Run both readers through a window.** Keep the Better Auth Worker answering for its own cookie
  while effect-auth issues new sessions, and in the app's hook fall back to the old reader when
  only the old cookie is present. Retire the fallback after the old sessions' maximum lifetime.

Either way, the **fast-path predicate has to change with the name**. The check that skips session
resolution for a cookieless request must look for the new cookie. Configure
`SessionResolution.detectCredential` (or the SvelteKit hook's `cookies` option) with the same
`SessionCookieNaming` the auth handler uses. A predicate still looking for
`better-auth.session_token` makes every signed-in request skip resolution.

### The `role` additional field

Better Auth's most common customisation is a `role` `additionalField` on the user. In effect-auth:

- **Storage.** The role lives in the user's attribute bag (`auth_users.attributes.role`). The data
  migration copies the column into the bag, as for any additional field (§6).
- **Writes.** `role` is a server-only attribute by default (`UserServiceConfig.serverOnlyAttributes`,
  default `["role"]`). A user can't set it through the profile update, and the session cookie
  cache never carries it to the browser. Change it with the admin endpoints, or with
  `UserService` from trusted code.
- **Meaning.** An ordered set of roles is a `Ladder`. `Ladder.make(["user", "moderator", "admin"])`
  gives `atLeast` checks, named axes, and `Policy.roleAtLeast` for the policy kernel.
- **The database `CHECK`.** effect-auth-drizzle's `ladderCheck` renders the ladder as a `CHECK`
  constraint, so the column rejects a role off the ladder, as the Better Auth app's own `CHECK`
  did. Keep the constraint and the ladder in one place.

### The `apiKey` plugin

| Better Auth `apiKey`                         | effect-auth                                                                                                                                                                                            |
| -------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| `x-api-key` header                           | Read by default (`CredentialConfig.apiKeyHeaders`, default `["x-api-key"]`). A request carrying one resolves as a `machine` credential (`Authorizer.CredentialClass`).                                 |
| Session from key (`enableSessionForAPIKeys`) | No synthetic session. The key resolves the principal directly. Policies that should not admit machine callers ask for the `interactive` credential class instead of relying on a session being absent. |
| Per-key rate limit                           | `ApiKey.rateLimit` (`{ maxRequests, windowMs }`), enforced by `ApiKeyService.verifyWithRateLimit`.                                                                                                     |
| `remaining` / refill                         | `remaining`, `refillAmount`, `refillInterval` and `refillMax` on the key ([ADR 0012](../adr/0012-api-key-design.md)).                                                                                  |
| `referenceId`                                | A key belongs to `userId`. Carry any other owner reference in `metadata`.                                                                                                                              |
| Stored key                                   | Digest only (`keyHash`), with `start` and `prefix` kept for display. Better Auth's stored hashes do not carry over: re-issue keys, or verify old ones through a custom path during a window.           |

`ApiKeyStore` has no effect-auth-sql implementation (see below): use the `KeyValueStore` default
or bring your own.

## 8. Not covered, or different by design

Be honest with yourself about these before committing:

- **No CLI and no schema generation.** Better Auth's `generate`/`migrate` inspect your config and emit a schema. effect-auth ships a fixed DDL list in `packages/sql` and otherwise expects you to own your migrations. An Alchemy app can let the `AuthSchema` resource reconcile that DDL on every deploy, on D1 or on Postgres over Hyperdrive; [Auth as an internal Worker on Alchemy](alchemy-internal-worker.md#living-with-drizzle-kit-migrations) covers how that sits beside drizzle-kit migrations.
- **No social OAuth HTTP endpoints and no passkey HTTP endpoints.** Both features exist as services with full functionality; the routes are yours to mount. This is the largest single chunk of work in a typical migration.
- **No `auth.api.*` server-side call surface.** The equivalent is calling the service directly inside an `Effect`, which means your call sites become Effects (or `Effect.runPromise` boundaries).
- **You must adopt Effect.** Layers, `Context.Service`, typed error channels and `Effect.gen` are not an implementation detail you can ignore — they are the API. This is the real cost of the migration and it is not small.
- **Sessions do not carry over cleanly** (§6). Plan a forced re-authentication. Password hashes are a separate question with a happier answer: an Argon2id hash carries over unchanged, because `@thomasfosterau/effect-auth-argon2` verifies against the parameters stored in the PHC string itself. Only a hash in a format effect-auth cannot verify — Better Auth's default scrypt among them — needs the custom-`PasswordHasher` or forced-reset path in §6.
- **No user email on the user record.** Code that reads `user.email` must go through `IdentifierStore` (or the derived optional `email` / `emailVerified` fields the HTTP `UserView` still exposes for wire compatibility).
- **Protocol _server_ plugins have no plugin-config equivalent.** The tier Better Auth exposes as plugins — OIDC provider, SSO, SCIM, MCP dynamic client registration, the device grant — ships here too ([ADR 0017](../adr/0017-batteries-included-auth-framework.md) supersedes the older "out of scope" record), but as services and stores you provide with layers; there is no plugin object to port across.
- **Feature gaps at the edges.** Better Auth plugins with no effect-auth counterpart today include Stripe/polar-style billing integrations, SIWE, and the various framework-specific server helpers. Conversely, effect-auth has features Better Auth does not: SCIM 2.0 provisioning, a policy kernel with Cedar-shaped semantics (`Auth.Policy`, `Auth.Authorizer`, `protectedField`), and hierarchical teams.
- **`packages/sql` does not implement every contract.** `OneTimeTokenStore`, `TrustedDeviceStore`, `PhoneOtp*Store`, `OrganizationStore`, `AdminUserStore`, `ApiKeyStore`, the OIDC provider stores, `SsoProviderStore`, `SamlReplayStore`, `DeviceAuthorizationStore`, `GoogleOneTapNonceStore`, `JwtKeyStore`, `OtpSecondFactorStore`, `AnonymousUserStore`, `AccountManagementStore` and `PolicyStore` are not covered — use the `KeyValueStore` defaults in `KeyValueStores.ts` or bring your own ([`byo-stores.md`](./byo-stores.md)).

## Further reading

- [ARCHITECTURE.md](../ARCHITECTURE.md) — the module map and store inventory
- [DESIGN.md](../DESIGN.md) — why the API looks the way it does
- [byo-stores.md](./byo-stores.md) — implementing store contracts over your own database
- [client.md](./client.md) — the browser client and framework bindings
- [better-auth-parity.md](../better-auth-parity.md) — the target architecture and its deliberate deferrals
