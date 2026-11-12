# @thomasfosterau/effect-auth-alchemy-postgres

## 0.1.2

### Patch Changes

- 9b63f86: **Security hardening (#631):** every adapter now depends on `@thomasfosterau/effect-auth` through a caret range (`^0.x.y`) instead of an exact pin. A consumer who upgrades the core within a minor (say, for a security patch) gets one copy of it, and no adapter keeps running a nested, unpatched core of its own. Under 0.x a caret range covers one minor, so the adapters are released with every core minor.
  
  **effect-auth-drizzle (#635):** the `drizzle-orm` peer range is bounded to the tested lines, `>=0.44.0 <0.46.0 || >=1.0.0-rc.5 <2`, and a new drizzle minor joins it once CI has run against it. The unused optional `@types/pg` peer is dropped.
- f49ee5d: Drop redundant default type arguments from the published declarations (`Redacted.Redacted<string>` is now written `Redacted.Redacted`, `Effect.Effect<A, E, never>` is `Effect.Effect<A, E>`, and so on); every type is unchanged (#503). Values that were stringified with `String(…)` are now converted explicitly: an OAuth profile id that is neither a string nor a number becomes `""` rather than `"[object Object]"`, the unsupported `id_token` algorithm error formats the header value (`"HS256"`), and a Twilio error body whose `code` or `message` is not a string is rendered as JSON.
- cc2bac6: Import Effect's helper modules (`Array`, `Option`, `Predicate`, `Record`, `Schema`, `String`) from their own entry points (`effect/Array`, …) rather than the `effect` barrel. The emitted `dist/` and `.d.ts` change their import specifiers only; no API or behaviour changes.
- a2624ea: Purge expired rate-limit rows (#686). `./sql`'s `purgeExpired` (and so the Alchemy packages' `purgeExpired`) now also deletes the `auth_rate_limits` rows whose window and block have both passed, in one `DELETE`, and `PurgeExpiredResult` gains `rateLimits`, the count it deleted. The drizzle package adds `RateLimitStore.purgeExpired(tables)`, one `DELETE` of the same rows from its rate-limit table. A row inside its window or still blocked stays.
- Updated dependencies [8d7fe03]
- Updated dependencies [c80f91c]
- Updated dependencies [fd32f3f]
- Updated dependencies [eafa773]
- Updated dependencies [701eebc]
- Updated dependencies [fe036f1]
- Updated dependencies [de98263]
- Updated dependencies [3829977]
- Updated dependencies [4037bcf]
- Updated dependencies [9598882]
- Updated dependencies [dd8715a]
- Updated dependencies [ea7f4ea]
- Updated dependencies [325f231]
- Updated dependencies [4649a7b]
- Updated dependencies [d66403e]
- Updated dependencies [f49ee5d]
- Updated dependencies [cf1e3c9]
- Updated dependencies [7a651a3]
- Updated dependencies [cc2bac6]
- Updated dependencies [1e7d8f4]
- Updated dependencies [8b65156]
- Updated dependencies [2096e2a]
- Updated dependencies [efba66d]
- Updated dependencies [7d9579e]
- Updated dependencies [4037bcf]
- Updated dependencies [e2ff7f7]
- Updated dependencies [6d33e11]
- Updated dependencies [b386606]
- Updated dependencies [32ebf2d]
- Updated dependencies [a2624ea]
- Updated dependencies [211f399]
- Updated dependencies [93685f4]
- Updated dependencies [f43b53d]
- Updated dependencies [7f3ab3d]
- Updated dependencies [68faced]
- Updated dependencies [b96f201]
- Updated dependencies [c50edb9]
- Updated dependencies [63e45ac]
- Updated dependencies [e57ea3c]
- Updated dependencies [e1770e3]
- Updated dependencies [88cd0a1]
  - @thomasfosterau/effect-auth@0.3.0

## 0.1.1

### Patch Changes

- 3c140a6: Ship `CHANGELOG.md` in the published tarball, so the release notes can be read from `node_modules` (#545).
- Updated dependencies [55637b0]
- Updated dependencies [3c140a6]
- Updated dependencies [1cacf66]
- Updated dependencies [e52a95d]
- Updated dependencies [7f12561]
- Updated dependencies [47534bb]
- Updated dependencies [4c48eb4]
  - @thomasfosterau/effect-auth@0.2.0

## 0.1.0

### Minor Changes

- ef36449: First release of `@thomasfosterau/effect-auth-alchemy-cloudflare` on Effect 4, built and tested against `effect` `4.0.0` and `alchemy` `2.0.0-beta.80` (#250).
  
  **Breaking peer ranges:** the package now requires `alchemy >=2.0.0-beta.80` and `effect >=4.0.0`. alchemy beta.79 and earlier import `effect/unstable/*`, which Effect removed in rc.118, so they can't load beside any `effect` this package supports; beta.80 is the first alchemy release that imports only `effect/*` paths, and it peers on `effect ^4.0.0` itself. So this package's `effect` floor is `4.0.0`, above the `>=4.0.0-rc.118` floor the other effect-auth packages keep. The packed `dist/` is smoke-tested on `4.0.0`.
  
  **Breaking — the D1 binding moves from `AuthSchema` props to `AuthSchemaProvider`.** Alchemy persists resource props as plain data and replays them on destroy, so a live binding passed as a prop was already gone by the time `delete` ran, and `dropOnDelete: true` would fail on any real `alchemy destroy`, not just under test. Mount the provider with the binding instead (`AuthSchemaProvider({ database: db })`, or `AuthSchemaProvider({ databases: { primary, tenants } })` for several) and declare the resource with plain data only: `AuthSchema("auth-schema", { dropOnDelete: true })`, using `database: "tenants"` to select a named binding. The provider must stay registered with its binding for destroys as well as deploys; a resource naming a database the provider doesn't hold now fails with the new `UnknownDatabaseError` rather than silently skipping the drop. New exports: `AuthSchemaProviderOptions`, `UnknownDatabaseError`, `DEFAULT_DATABASE`. Because the provider layer is built in `Alchemy.Stack`'s `providers` field, the D1 handle must be obtainable outside the program body, the same shape as alchemy's own providers taking credentials at registration.
- 091cbb2: Postgres over Hyperdrive (#184). `@thomasfosterau/effect-auth-alchemy-postgres` provides every effect-auth store over a Cloudflare Hyperdrive binding (`Postgres.layer(env.HYPERDRIVE)`) or a Postgres URL, plus `migrate`, `purgeExpired` and `clientLayer`, all through `@effect/sql-pg`, a required peer. Its `AuthSchema` resource and `AuthSchemaProvider` reconcile the schema in a Postgres database on deploy: pass `database(url)`, or `postgresDatabase(layer)` over any Postgres `SqlClient` layer, alone or registered by name.
- 51edf74: Built for Effect `4.1` (#501, #499).
  
  **Breaking peer ranges:** every package above now requires `effect ^4.1.0`, and the Alchemy packages require `alchemy` `2.0.0-beta.85` (effect-auth-alchemy-postgres also `@effect/sql-pg ^4.1.0`). Effect 4.1 removed the root `Crypto` module in favour of `effect/crypto`; alchemy beta.84 and earlier import that removed module, and beta.85 peers on `effect ^4.1.0` itself.
  
  **Breaking — randomness and digests come from `effect/crypto`.** Services that yielded `Crypto.Crypto` now yield `SecureRandom.SecureRandom`, and the ones that hash (OAuth PKCE, the OIDC provider, WebAuthn, `HaveIBeenPwnedPlugin`) also yield `Digest.Digest`. Every `static layer` still provides both through `PlatformCrypto.layer`, so only code that builds a service from its raw `make` changes: provide `SecureRandom.layerWebCrypto` and `Digest.layerWebCrypto` (or your own implementations) where it provided `Crypto.Crypto`. The OTP primitives that took a `Crypto` instance (`generateBase32Secret` and friends) take a `SecureRandom` service instead. `OAuthProvider.generateAuthorizationUrl`, `generatePKCE` and `SsoService.signIn` add `Digest.Digest` to their requirements.
  
  `layerMemoryKeyValueStore` implements `KeyValueStore.keys`, which Effect 4.1 added to the interface. effect-auth-alchemy-cloudflare's `D1Client` names its driver (`SqlClient.driver` is `"d1"`).
- cc67083: Framework packages, form components, and adapter reworks.
  
  - The Svelte binding moved out of the client into its own package, `@thomasfosterau/effect-auth-svelte`, authored as Svelte 5 runes `.svelte` components, with six out-of-the-box headless form components: `SignInForm`, `SignUpForm`, `PasswordResetRequestForm`, `PasswordResetConfirmForm`, `MagicLinkForm`, `EmailOtpForm`. The client package no longer has `./react`, `./svelte`, `./vue`, or `./types` subpaths; wire types come from the core package's `Http` namespace, and the client's `emailOTP`/`phoneOTP` sections are now `emailOtp`/`phoneOtp`.
  - `@thomasfosterau/effect-auth-drizzle` supports PostgreSQL, SQLite, and MySQL through per-dialect table modules (`Pg`, `Sqlite`, `MySql`) over a structural database seam, and its store modules are namespaced with `make`/`layer` exports (`SessionStore.make`, `UserStore.layer`, `Requests.layer`, ...).
  - `@thomasfosterau/effect-auth-alchemy-cloudflare` was rebuilt: the bespoke D1 wrapper and hand-rolled stores are gone; a D1-backed `SqlClient` now drives the shared `@thomasfosterau/effect-auth/sql` stores, and the `AuthSchema` resource runs through the real Alchemy engine.
- 8213f5b: `purgeExpired` deletes the magic-link and email-OTP rows whose expiry has passed and reports how many it deleted from each table. No store deletes them on its own, and the sends that hide whether an account exists write one for any address, so a host schedules this (a cron trigger on Workers, a timer on a long-lived server) to keep the tables bounded. effect-auth/sql exports it over the ambient `SqlClient`; effect-auth-alchemy-cloudflare exports `purgeExpired(db)` over a D1 binding. The schema gains an `expires_at` index on each of the two tables, which `migrate` adds on the next run (#420).
- ca3abfb: Every SQL `createUser` seam (`EmailPasswordStore`, `OAuthUserStore`, `MagicLinkUserStore`, `EmailOtpUserStore` and `AdminUserStore`) resolves to core's `CreateUserResult`, `{ user, created: true }`: each is a plain `INSERT` with a fresh id, so every success is a new user (#406).
- 9ff7ded: The SQL `IdentifierStore` implements `replace`: it inserts the new identifier and deletes the old one inside `sql.withTransaction`, so a value another user holds is refused by the `(type, value)` unique index and the transaction rolls back with the old identifier in place. The release is a `DELETE … RETURNING` guarded on the old identifier's id, user, type and value: when it deletes nothing, the new identifier is deleted again and `replace` resolves to `null`, so of two concurrent replaces of the same identifier one succeeds (at PostgreSQL's default READ COMMITTED isolation; at stricter levels the losing call fails with a serialization error, surfaced as `AuthError`). On Cloudflare D1 (`@thomasfosterau/effect-auth-alchemy-cloudflare`), which has no transactions, the two statements autocommit in the same order, so a failure between them leaves the user holding both identifiers, never neither, and confirming an email change again releases the old one; the losing call of two concurrent replaces deletes its new identifier in a statement of its own, so a failure before it leaves the user holding both new identifiers (#381).

### Patch Changes

- fdbe133: Rebuild `@thomasfosterau/effect-auth-alchemy-cloudflare` on `@alchemy.run/cloudflare`'s D1 services (ADR-0023). `D1Client`, `layer`, `migrate` and `purgeExpired` take the `QueryDatabaseClient` that `Cloudflare.D1.QueryDatabase(database)` binds, and need the event's `RuntimeContext`; the structural `D1Database`, `D1PreparedStatement` and `D1Result` types are removed. A transaction is sent to D1 as `batch()`es, so the stores' multi-step writes between two reads now commit atomically. `AuthSchema(id, database)` is now an Alchemy Action over a `Cloudflare.D1.Database` (provide `Cloudflare.D1.QueryDatabaseLocal` on deploy); `AuthSchemaProvider`, `AuthSchemaProps`, `AuthSchemaProviderOptions`, `AuthSchemaDatabase`, `DEFAULT_DATABASE`, `UnknownDatabaseError` and `dropOnDelete` are removed. `@thomasfosterau/effect-auth-alchemy-postgres`'s `AuthSchema` doc comment now describes the D1 counterpart as an Action.
- 0def0c5: The `effect` peer range is now `^4.1.0` (was `>=4.1.0`), and effect-auth-alchemy-postgres's `@effect/sql-pg` peer is `^4.1.0` too. The floor is unchanged: the packages need `effect/crypto`, which first shipped in Effect 4.1. The caret form stops the range from claiming a future Effect 5 it was never tested against.
- 02df078: Publish from the library tooling standard (#222). Every package now takes its dependency versions
  from the workspace's strict pnpm catalog and its published peer ranges from `catalog:peers`, so the
  ranges consumers see are declared once; the published ranges themselves are unchanged. Releases are
  published by `pnpm publish` through npm OIDC trusted publishing (provenance is left to npm, never forced). The packages' `build` / `test` / `typecheck` scripts moved into Vite+ tasks
  (`build`, `test:unit`, `check`), so the published manifests no longer carry them.
- cbeda0d: Document the supported dialects. `@thomasfosterau/effect-auth/sql` supports SQLite, Cloudflare D1 and PostgreSQL. MySQL is not supported: its upserts and counters use `ON CONFLICT`, which MySQL lacks, so MySQL users should take `@thomasfosterau/effect-auth-drizzle`'s MySQL tables (#260). `@thomasfosterau/effect-auth-alchemy-cloudflare`'s module docs say the sql DDL is valid on SQLite, D1 and PostgreSQL, not MySQL.
- Updated dependencies [84c9180]
- Updated dependencies [8ebcb4a]
- Updated dependencies [a1b01ae]
- Updated dependencies [b9a8437]
- Updated dependencies [68709bf]
- Updated dependencies [b2e7fd4]
- Updated dependencies [bbb24fe]
- Updated dependencies [106bb64]
- Updated dependencies [95f9ba6]
- Updated dependencies [ca3abfb]
- Updated dependencies [7f5206e]
- Updated dependencies [29d011c]
- Updated dependencies [afd57ae]
- Updated dependencies [20cde53]
- Updated dependencies [c1b0737]
- Updated dependencies [416fc73]
- Updated dependencies [2d26680]
- Updated dependencies [aa7b6e6]
- Updated dependencies [048e031]
- Updated dependencies [69b1d18]
- Updated dependencies [6d6bf02]
- Updated dependencies [61847b0]
- Updated dependencies [89802ec]
- Updated dependencies [51edf74]
- Updated dependencies [dcffe28]
- Updated dependencies [0def0c5]
- Updated dependencies [8d904a6]
- Updated dependencies [03bdfea]
- Updated dependencies [42d0f03]
- Updated dependencies [b165354]
- Updated dependencies [cc67083]
- Updated dependencies [fa438cf]
- Updated dependencies [5ab2078]
- Updated dependencies [9ff7ded]
- Updated dependencies [78dac5f]
- Updated dependencies [78dac5f]
- Updated dependencies [41ce19d]
- Updated dependencies [b1fbf57]
- Updated dependencies [ce56aeb]
- Updated dependencies [e03530e]
- Updated dependencies [4c70cd2]
- Updated dependencies [c1ba5f6]
- Updated dependencies [02df078]
- Updated dependencies [4e6293b]
- Updated dependencies [2484af6]
- Updated dependencies [6bee50c]
- Updated dependencies [90d7a79]
- Updated dependencies [d767491]
- Updated dependencies [7f5206e]
- Updated dependencies [e6c3a64]
- Updated dependencies [39654ad]
- Updated dependencies [f4f6606]
- Updated dependencies [624a9b5]
- Updated dependencies [373bb87]
- Updated dependencies [ec17f5d]
- Updated dependencies [8e5fc41]
- Updated dependencies [504ae0d]
- Updated dependencies [c99689b]
- Updated dependencies [1d47091]
- Updated dependencies [3de5d6a]
- Updated dependencies [a108a36]
- Updated dependencies [624f356]
- Updated dependencies [ef58828]
- Updated dependencies [00aa6e9]
- Updated dependencies [8213f5b]
- Updated dependencies [d2d8163]
- Updated dependencies [856d6fe]
- Updated dependencies [8235dad]
- Updated dependencies [5a48055]
- Updated dependencies [89749b6]
- Updated dependencies [213497b]
- Updated dependencies [5ab875a]
- Updated dependencies [f5bf843]
- Updated dependencies [8fce539]
- Updated dependencies [a517a32]
- Updated dependencies [5e1d6ce]
- Updated dependencies [311e9cb]
- Updated dependencies [a81a752]
- Updated dependencies [50a4084]
- Updated dependencies [36788a7]
- Updated dependencies [68e339a]
- Updated dependencies [2ba63b6]
- Updated dependencies [408285d]
- Updated dependencies [a3131b6]
- Updated dependencies [f87095c]
- Updated dependencies [2510ce4]
- Updated dependencies [45e863a]
- Updated dependencies [fed9d0c]
- Updated dependencies [03a3219]
- Updated dependencies [ca3abfb]
- Updated dependencies [9ff7ded]
- Updated dependencies [cbeda0d]
- Updated dependencies [8f78034]
- Updated dependencies [f7bafc0]
- Updated dependencies [c092987]
- Updated dependencies [ef0207d]
- Updated dependencies [bfa558e]
- Updated dependencies [3875062]
- Updated dependencies [1031ed5]
- Updated dependencies [5ab2078]
- Updated dependencies [9b1fe6f]
  - @thomasfosterau/effect-auth@0.1.0
