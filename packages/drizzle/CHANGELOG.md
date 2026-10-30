# @thomasfosterau/effect-auth-drizzle

## 0.2.0

### Minor Changes

- 9069e03: Bind the drizzle stores to Effect-shaped drivers, and let the application own the handle's
  lifetime (#181).
  
  - **Effect drivers.** `.execute()` returns a `Promise` on the classic drivers and an `Effect`
    on drizzle's Effect drivers (`drizzle-orm/effect-postgres`, `effect-pglite`,
    `effect-mysql2`, `effect-sqlite-*`, new in drizzle `1.0`). `DrizzleResult` is now the union
    of the two and the store layer adapts at runtime, so an Effect-shaped handle reaches the
    database with no Promise round trip anywhere between `Auth.SessionStore` and the driver.
    `effectDatabaseLayer` is the door for those handles; it checks the shape of the builder
    chain structurally, because drizzle's Effect entrypoints only exist from `1.0` and this
    package's peer range starts at `0.44`.
  - **Late-bound handles.** `databaseLayer` and `effectDatabaseLayer` now accept an
    `Effect` yielding a handle as well as a handle. The `Effect` is run once per query, in the
    calling fiber, so a connection held in a `Context.Reference` follows the request that set
    it — what a request-scoped pool needs on Cloudflare Workers, where a pool's sockets are
    pinned to the request that opened them. No `AsyncLocalStorage`: the request scope is the
    Effect context.
  
  Passing a plain handle pins it for the life of the layer. The `DrizzleDatabase` service shape
  is `{ database: Effect<AuthDatabase> }`, so code that builds the layer by hand provides
  `{ database: Effect.succeed(db) }`.
- 9ff7ded: Both drizzle identifier stores implement `IdentifierStore.replace`, on PostgreSQL, SQLite and MySQL. The default store reads the identifier it replaces, inserts the new one, then deletes the old one; it opens no transaction of its own, so on a handle inside the application's transaction the two writes commit together, and otherwise a failure between them leaves the user holding both, never neither. `SingleTableIdentifierStore` rewrites the row in one `UPDATE users SET email, email_verified[, email_verified_at] WHERE id = <user> AND email = <old>`, on nullable and `NOT NULL` columns alike, keeping the user's id and creation time as the identifier's; a stale call writes nothing and resolves to `null`. Core email change works on both stores (#381).
- d0ba9c5: Promote attributes to real columns (#182). The users entry of `defineSchema` takes
  `promoted: { role: "role", … }` — attribute name to a column that reads back as a string, number,
  boolean or `null` — and the user store (direct and batched reads) presents each promoted column in
  `user.attributes` under that name, so `attributes.role` readers see the application's real, typed,
  `CHECK`-constrained `users.role` column. The column is the sole authority for its key: a value under
  the same key in the `jsonb` bag is ignored, and a `NULL` column leaves the key absent. The users
  table's `attributes` mapping is now optional, so a table whose every attribute is a column — the
  shape the applications' `users` tables have — needs no bag at all.
- c10c03d: Let the stores run against tables this package did not define (#182).
  
  `Pg.defineTables()` could rename the three auth tables and nothing else, so an application
  adopting effect-auth **in place** — one whose entity graph already has foreign keys into
  `users.id`, and whose primary keys are `uuid` rather than `text` — had to migrate its whole
  graph to meet this package's schema. `defineSchema` inverts that: it pairs each table with a
  mapping from the fields the stores need to the columns _that_ table actually has, and the
  stores project through the mapping.
  
  ```ts
  const stores = layer(
    defineSchema({
      sessions: { table: appSessions, columns: { id: "digest", userId: "account", ... } },
      users: { table: appUsers, columns: { id: "key", name: "displayName", ... } },
      identifiers: { table: appHandles, columns: { id: "key", type: "kind", ... } },
    }),
  );
  ```
  
  The mapping is checked at the application's own call site: `ColumnKey` picks out exactly
  those keys of a table whose selected value is assignable to the type the store needs, so
  naming a `text` column for `expiresAt`, a non-nullable one for `verifiedAt`, or a column that
  does not exist, is a compile error rather than a runtime surprise. Column names are free;
  column types are free as long as they read back as the value the domain uses, which is what
  makes `uuid` keys a mapping rather than a migration.
  
  Every store factory — `SessionStore.layer`, `UserStore.layer`, `IdentifierStore.layer`,
  `Requests.layer` and the aggregate `layer` — now takes `Tables | AuthSchema`, so passing
  `Pg.tables`, `Sqlite.tables`, `MySql.tables` or a `defineTables(...)` result works exactly as
  before; the fixed-shape path builds the identity mapping and runs the same code. Writes still
  cover only the mapped columns, so an application column the stores know nothing about needs a
  database-level default. Promoting a named attribute to a real typed column the stores write,
  and the single-table `users.email` identifier mode, are the remaining parts of #182.
  
  The one behaviour change on the existing path: reads now project the columns the stores
  actually use instead of `SELECT`ing every column of the table, so `effect_auth_users.password_hash`
  is no longer fetched by `UserStore`. `AuthDatabase.select` gained a projecting overload for
  this, and `DrizzleSelectFrom`/`DrizzleSelectFiltered` are now aliases over row-shaped
  `DrizzleRowSelectFrom`/`DrizzleRowSelectFiltered` — same meaning, same type arguments.
- b6f7dd0: Initial release of `SingleTableIdentifierStore`, an opt-in `IdentifierStore` that keeps a user's email identifier on the application's own `users` row: the address in `email`, its verified flag in `email_verified`, and the row's `created_at` as the identifier's creation time. An application whose users table already holds the login address can use it without an identifiers table. It holds one identifier per user, an email. Any other identifier type, and a second address for the same user, are refused with an `AuthError`. Enter through `SingleTableIdentifierStore.layer(SingleTableIdentifierStore.defineUsers({ ... }))`. The default multi-identifier `IdentifierStore` is the one `layer()` provides and stays the default.
  
  `defineUsers` accepts a `NOT NULL` `email` column as well as a nullable one; the store reads which from the column. On a `NOT NULL` column a targeted delete of an address is refused with an `AuthError` and the address stays, and `deleteByUser` leaves the row for account deletion to remove. Email change works on both shapes: the store's `replace` rewrites the address in one `UPDATE` guarded on the old address, so a `NOT NULL` row is never left `NULL`. An optional `emailVerifiedAt` mapping stores and reports the verification time; without it, `verifiedAt` is not stored. The README gives the unique-index DDL per dialect.
- 8d904a6: Built for Effect `4.0.0-rc.118`.
  
  Every package above requires `effect >=4.0.0-rc.118`. The published `dist/` imports rc.118's module paths (`effect/http-api`, `effect/http`, `effect/sql`, `effect/persistence`, `effect/process`, and so on), which earlier Effect releases don't have, so install `effect` and any `@effect/*` companion at rc.118 or later.
  
  - **An empty encryption secret is a configuration error.** The stock config providers read an empty environment variable as absent, which would silently turn encryption at rest off. So `JWT_ENCRYPT_PRIVATE_KEY_SECRET=""`, `OAUTH_ENCRYPT_TOKENS_SECRET=""` and `TWO_FACTOR_ENCRYPT_SECRET=""` fail `jwtServiceConfig`, `oauthServiceOptionsConfig` and `multiFactorConfig` at startup with a `ConfigError` naming the variable ("set but empty"). An **unset** variable means encryption is off. Unset or fix any such variable that your templating or secrets manager renders as `""`. Empty `JWT_ISSUER` and `TRUSTED_DEVICE_SECRET` fail as missing, and an empty `TRUSTED_DEVICE_MAX_AGE_MS` uses its default (#252).
- cc67083: Framework packages, form components, and adapter reworks.
  
  - Framework bindings moved out of the client into their own packages — `@thomasfosterau/effect-auth-react`, `-svelte`, `-vue`, and the new `-solid` — each with idiomatic authoring (React JSX, Svelte 5 runes `.svelte` components, Vue SFCs, Solid JSX with a `"solid"` export condition) and the same six out-of-the-box headless form components: `SignInForm`, `SignUpForm`, `PasswordResetRequestForm`, `PasswordResetConfirmForm`, `MagicLinkForm`, `EmailOtpForm`. The client package no longer has `./react`, `./svelte`, `./vue`, or `./types` subpaths; wire types come from the core package's `Http` namespace, and the client's `emailOTP`/`phoneOTP` sections are now `emailOtp`/`phoneOtp`.
  - `@thomasfosterau/effect-auth-drizzle` supports PostgreSQL, SQLite, and MySQL through per-dialect table modules (`Pg`, `Sqlite`, `MySql`) over a structural database seam, and its store modules are namespaced with `make`/`layer` exports (`SessionStore.make`, `UserStore.layer`, `Requests.layer`, ...).
  - `@thomasfosterau/effect-auth-alchemy` was rebuilt: the bespoke D1 wrapper and hand-rolled stores are gone; a D1-backed `SqlClient` now drives the shared `@thomasfosterau/effect-auth-sql` stores, and the `AuthSchema` resource runs through the real Alchemy engine.
- fa438cf: `IdentifierStore.create` gains a typed refusal, `IdentifierRefusedError`, for an identifier a store cannot hold by its own shape: a store that keeps one email per user refuses a second, and an emails-only store refuses any other type. `claimIdentifier` passes it through. SCIM answers it with `409` and `scimType: "uniqueness"` instead of a `500`, so a `userName` change on a one-email store reaches the IdP as a request to reconcile. The other flows (sign-up, email change, username, phone number, admin extras) report it as an `AuthError`, as before, through the new `refusalAuthError` (#379).
  
  effect-auth-drizzle's `SingleTableIdentifierStore` raises `IdentifierRefusedError` where it raised `AuthError` for those two refusals; a user with no row is still an `AuthError`.
- 8e5fc41: Add owned-material read access and its drizzle rendering (#190).
  
  `Auth.OwnedAccess.make({ guards, viewPrivate })` interprets a three-state visibility axis
  (`public | followers | private`) plus an orthogonal `draft` flag, in two shapes built from the same
  facts: `canView(row)`, the per-row predicate (never fails — a `false` is a 404 to the caller,
  decided by the policy kernel over `OwnedAccess.policies`), and `readScope`, the per-request
  `all | public | member(userId, following)` scope a list renders as its `WHERE`. The `followers`
  state resolves through the `IsFollower` service (a row check plus the viewer's follow set) read with
  `Effect.serviceOption`, so a runtime that does not provide it fails closed; `isFollowerNever` makes
  that explicit.
  
  `@thomasfosterau/effect-auth-drizzle` adds `ownedListFilter(columns)(scope)`, which renders the scope
  over any table's or view's owner / visibility / draft columns — the follow set nested as an
  `owner IN (SELECT …)` subquery, never a materialised list — and `isFollowerLayer`, the follower seam
  over an application's own follow table. A property test runs the rendered filter and `canView` over
  one corpus in PGlite and requires them to agree on every row.
- 213497b: `UserStore` holds no credentials: its contract is `get` alone. Sign-in reads and
  writes the password hash through
  `Auth.Email.EmailPasswordStore.getPasswordHash`/`setPasswordHash`, which
  `@thomasfosterau/effect-auth-sql` and `@thomasfosterau/effect-auth-drizzle`
  implement. In `@thomasfosterau/effect-auth-drizzle`, `Requests.getUser` /
  `UserStore.GetUser` batch user reads.
- 311e9cb: Make the `role` attribute safe to authorize on (#193, the parts that pair with the ladder).
  
  - **Server-only attributes.** `UserService.updateUserAttributes` now refuses — with
    `InvalidInputError`, writing nothing — any key in `UserServiceConfig.serverOnlyAttributes`, which
    defaults to `["role"]`: a profile-update path built on it can no longer let a user set their own
    rung. **Behaviour change:** code that set `role` through `updateUserAttributes` must move to
    `AdminService.setRole` (or pass `UserService.layer({ serverOnlyAttributes: [] })` to opt out).
  - **Constrained values.** `AdminConfig.roles` (an app's `Ladder` satisfies it) makes `setRole` and
    `createUser` refuse a role off the ladder with `AdminError`, whichever door the role comes in by.
  - **Declared once.** `LadderSchema.rung(ladder)` is the ladder's rungs as a `Schema`, and
    `@thomasfosterau/effect-auth-drizzle`'s `ladderCheck(column, ladder)` is the matching `CHECK`
    expression (rungs inlined as quoted literals), so the type, the runtime check and the database
    backstop come from one declaration.

### Patch Changes

- b9a8437: With `antiEnumeration: true`, email and password sign-up answers an address found taken at the insert (a lost race, or a store whose `createUser` reports `created: false`) exactly as it answers one the pre-check finds taken: it hashes the submitted password and returns the same no-session result, so neither the response nor its timing tells an existing account apart (#410).
  
  `CreateUserResult` and every `createUser` seam's docs state that a writer leaves an existing user's row unmodified: a plain `INSERT` that lets the unique index fail, or `ON CONFLICT DO NOTHING` followed by a select, and never `ON CONFLICT DO UPDATE`. effect-auth-drizzle's `SingleTableIdentifierStore` docs and README say the same for `onConflictDoNothing` and `onConflictDoUpdate`, and the README's writers return the user's `name`.
- 61847b0: Every exported symbol has a doc-comment summary that shows in editor hovers: the core's service classes (with the stores each one requires), configs and results, the `Condition` and `Policy` scope constructors, the `Observability` record helpers, the HTTP list views and error schemas, the SQL stores and their layers, drizzle's row types and every `databaseLayer` overload, and `AuthClientOptions`. `hashToken` carries its own doc comment, and the client module overview opens with its summary rather than a tag line.
  
  Doc comments on `SessionResolution.resolveFailOpen` and `resolveAtEdgeFailOpen` (`http/RemoteSession.ts`) point at `docs/ARCHITECTURE.md` for the fail-open precondition.
- 416fc73: `SingleTableIdentifierStore`'s module docs and the README describe core sign-up on a `NOT NULL` `email` column: core passes the address to the application's `createUser` as `input.identifier`, the application's writer inserts the row holding it and reports `created: true`, and the claim that follows finds the address on the row and writes nothing more. On a nullable column the writer may also leave the address out, and the claim writes it. The README gives a writer for each column shape, both compiled and run in the package's tests (#380, #406).
- f79057f: Pin that the stores join an application's own drizzle Effect transaction (#181): inside
  `db.transaction(tx => …)` on `drizzle-orm/effect-postgres`, every store query — direct and batched
  through `Requests` — resolves its handle and runs on the transaction's own fiber, so it sees the
  transaction's uncommitted writes and commits or rolls back with it, with no service capture of the
  kind the applications' Better Auth adapter needed. Documented in the README.
- 89802ec: Built and tested against Effect `4.0.0`. The `effect` peer floor is unchanged (`>=4.0.0-rc.118`), so consumers still on `4.0.0-rc.118` keep working; `@effect/*` companions such as `@effect/sql-pg` should match whichever `effect` you install.
- dcffe28: Internal refactor for the Effect lint presets, with these observable edges:
  
  - `SessionService.createSession` / `setSessionAttributes`, `UserService.updateUserAttributes`, the `Username` sign-up and sign-in inputs and `ScimUserStore.create` take `Types.Attributes` (the readonly form of `Record<string, unknown>`); existing callers still type-check.
  - OAuth userinfo, OIDC discovery, JWKS and id_token segments that are not JSON objects now fail with `OAuthProviderError`, and a malformed JWKS document fails with `JwtError("Failed to fetch JWKS")`, instead of a defect or a confusing later error.
  - A CAPTCHA verification body of `null` now counts as a failed verification (`CaptchaError`) instead of a defect.
  - The sql stores decode their JSON columns with Schema, so a malformed stored value fails with the same `AuthError` instead of passing through unchecked; `readRbacPolicies` (drizzle) may return policies in a different order (decisions are unchanged).
  - Several thrown plain `Error`s (invalid header names, reserved principal types, malformed permissions, OTP URI and COSE key errors, session-cache config) are now tagged error classes with the same message; they are still `Error` instances.
  - resend and twilio wrap a failed non-2xx body read in a private tagged defect; saml reads non-object attribute bags as empty.
  - Effect handlers that became `Effect.fn` (auth middleware schemes, `requireScim`, JWT key rotation, decoy hashing) now emit a tracing span.
- 02df078: Publish from the library tooling standard (#222). Every package now takes its dependency versions
  from the workspace's strict pnpm catalog and its published peer ranges from `catalog:peers`, so the
  ranges consumers see are declared once; the published ranges themselves are unchanged. Releases are
  published by `pnpm publish` through npm OIDC trusted publishing (provenance is left to npm, never forced). The packages' `build` / `test` / `typecheck` scripts moved into Vite+ tasks
  (`build`, `test:unit`, `check`), so the published manifests no longer carry them.
- Updated dependencies [84c9180]
- Updated dependencies [8ebcb4a]
- Updated dependencies [a1b01ae]
- Updated dependencies [b9a8437]
- Updated dependencies [68709bf]
- Updated dependencies [b2e7fd4]
- Updated dependencies [bbb24fe]
- Updated dependencies [106bb64]
- Updated dependencies [95f9ba6]
- Updated dependencies [29d011c]
- Updated dependencies [afd57ae]
- Updated dependencies [20cde53]
- Updated dependencies [416fc73]
- Updated dependencies [2d26680]
- Updated dependencies [aa7b6e6]
- Updated dependencies [048e031]
- Updated dependencies [69b1d18]
- Updated dependencies [6d6bf02]
- Updated dependencies [61847b0]
- Updated dependencies [89802ec]
- Updated dependencies [dcffe28]
- Updated dependencies [8d904a6]
- Updated dependencies [03bdfea]
- Updated dependencies [42d0f03]
- Updated dependencies [b165354]
- Updated dependencies [fa438cf]
- Updated dependencies [5ab2078]
- Updated dependencies [9ff7ded]
- Updated dependencies [41ce19d]
- Updated dependencies [b1fbf57]
- Updated dependencies [ce56aeb]
- Updated dependencies [e03530e]
- Updated dependencies [4c70cd2]
- Updated dependencies [c1ba5f6]
- Updated dependencies [02df078]
- Updated dependencies [2484af6]
- Updated dependencies [6bee50c]
- Updated dependencies [90d7a79]
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
- Updated dependencies [624f356]
- Updated dependencies [00aa6e9]
- Updated dependencies [d2d8163]
- Updated dependencies [8235dad]
- Updated dependencies [5a48055]
- Updated dependencies [89749b6]
- Updated dependencies [213497b]
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
- Updated dependencies [a3131b6]
- Updated dependencies [f87095c]
- Updated dependencies [2510ce4]
- Updated dependencies [45e863a]
- Updated dependencies [03a3219]
- Updated dependencies [f7bafc0]
- Updated dependencies [c092987]
- Updated dependencies [ef0207d]
- Updated dependencies [bfa558e]
- Updated dependencies [3875062]
- Updated dependencies [1031ed5]
- Updated dependencies [5ab2078]
- Updated dependencies [9b1fe6f]
  - @thomasfosterau/effect-auth@0.2.0
