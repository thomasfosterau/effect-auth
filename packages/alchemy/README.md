# @thomasfosterau/effect-auth-alchemy

Cloudflare **D1** support for [`@thomasfosterau/effect-auth`](https://github.com/thomasfosterau/effect-auth/tree/trunk/packages/effect-auth) on
[Alchemy v2](https://v2.alchemy.run) — the TypeScript-native, Effect-based
Infrastructure-as-Code toolkit — covering both sides of the deploy:

- **Provider side** — the [`AuthSchema`](#the-authschema-resource) resource, so
  the Alchemy engine keeps the auth schema reconciled on every deploy.
- **Consumer side** — [`layer(db)`](#storage-layers), which turns a bound D1
  database into every effect-auth store.

The package is deliberately small. It contains no queries and no schema of its
own:

| Module       | What it is                                                            |
| ------------ | --------------------------------------------------------------------- |
| `D1Client`   | A `SqlClient` (from `effect/sql`) over a D1 binding.                  |
| `Storage`    | `layer(db)` / `migrate(db)` — the client wired to the SQL stores.     |
| `AuthSchema` | The Alchemy resource + provider that reconciles the schema on deploy. |

Every store, statement and DDL comes from
[`@thomasfosterau/effect-auth-sql`](https://github.com/thomasfosterau/effect-auth/tree/trunk/packages/sql), which implements the effect-auth
storage interfaces against `SqlClient` and is shared with every other SQL
deployment. D1 is SQLite, so the same tables and the same queries apply.

## Install

```sh
pnpm add @thomasfosterau/effect-auth-alchemy @thomasfosterau/effect-auth effect alchemy
```

`alchemy` (`>=2.0.0-beta.80`) and `effect` (`>=4.0.0`) are required peer
dependencies. The `effect` floor is 4.0.0 because alchemy beta.80 itself peers
on `effect ^4.0.0`; the other effect-auth packages accept `effect`
`>=4.0.0-rc.118`.
`@thomasfosterau/effect-auth-sql` comes along as a dependency.

## Storage layers

```ts
import { Layer } from "effect";
import * as Auth from "@thomasfosterau/effect-auth";
import * as AuthD1 from "@thomasfosterau/effect-auth-alchemy";

const sessionConfig: Auth.SessionConfig = {
  sessionExpiresIn: { activePeriod: 30 * 86_400_000, idlePeriod: 14 * 86_400_000 },
};

export const AppLayer = (db: AuthD1.D1Database) =>
  Auth.SessionService.layer(sessionConfig).pipe(
    Layer.provideMerge(Layer.mergeAll(AuthD1.layer(db), Auth.Hooks.Default)),
  );
```

`AuthD1.layer(db)` provides every store `@thomasfosterau/effect-auth-sql`
implements — `SessionStore`, `UserStore`, `EmailPasswordStore`,
`RateLimitStore`, `EmailVerificationStore`, `ChallengeStore`, `CredentialStore`,
`OAuthStateStore`, `OAuthAccountStore`, `PasswordResetStore`, `MagicLinkStore`,
`EmailOtpStore`, `MultiFactorStore`, `IdentifierStore`, … — all backed by
`auth_`-prefixed tables so they coexist with your application's own schema.

For a subset, provide `D1Client.layer({ db })` and pick the per-store layers
from `@thomasfosterau/effect-auth-sql` directly:

```ts
import { Layer } from "effect";
import * as Sql from "@thomasfosterau/effect-auth-sql";
import { D1Client, type D1Database } from "@thomasfosterau/effect-auth-alchemy";

export const SessionStores = (db: D1Database) =>
  Layer.mergeAll(Sql.SessionStoreLayer, Sql.UserStoreLayer).pipe(
    Layer.provide(D1Client.layer({ db })),
  );
```

`D1Database` is a structural type covering just what the client calls, so the
binding from `@cloudflare/workers-types`, Miniflare's local implementation and
the handle behind Alchemy's `Cloudflare.D1.QueryDatabase` all satisfy it.

### Transactions

D1 has no explicit transactions — `BEGIN` / `COMMIT` / `SAVEPOINT` are rejected
by the binding, and `batch()` is its only atomic primitive. `D1Client` therefore
answers those control statements locally instead of sending them, so the store
methods that ask for a transaction (`ChallengeStore.create`,
`OAuthStateStore.create`, `EmailOtpStore.upsert` — each a `DELETE` followed by
an `INSERT` — and `IdentifierStore.replace`, an `INSERT` followed by a
`DELETE`) run as autocommitted statements rather than failing. **Multi-step
writes are not atomic on D1.** Everything that needs atomicity is already a
single statement (`ON CONFLICT … DO UPDATE`, `UPDATE … RETURNING`).
`IdentifierStore.replace`, which email change uses, claims the new address
before it releases the old one, so a failure between the two statements leaves
the user holding both addresses, never neither; confirming the change again
releases the old one. The release is a `DELETE … RETURNING` guarded on the old
address, so of two concurrent replaces of the same address one succeeds; the
other finds nothing to release and deletes its own claim again, in a statement
of its own, so a failure before that statement leaves the user holding both new
addresses.

## The `AuthSchema` resource

`AuthSchema` keeps the effect-auth tables (`auth_users`, `auth_sessions`,
`auth_oauth_accounts`, …) reconciled inside a D1 database on every deploy.

- **Idempotent** — the DDL is all `CREATE TABLE IF NOT EXISTS`, so reconciling
  is cheap to repeat and additive schema changes from a library upgrade are
  picked up automatically.
- **Owns the schema, not the database** — the database is a binding the
  provider holds, not something this resource creates, so tearing the stack
  down never destroys auth data unless you opt in with `dropOnDelete: true`.

It is built with Alchemy's own `Resource` constructor, and `AuthSchemaProvider`
with Alchemy's own `Provider.succeed` — the same primitives `Alchemy.Random` and
`Cloudflare.D1.Database` are built from. The **engine** runs the lifecycle
(`read` → `diff` → `reconcile` / `delete`); nothing here re-implements it.

The **provider** takes the live D1 binding; the **resource** takes only plain
data:

```ts
import * as Alchemy from "alchemy";
import * as Cloudflare from "alchemy/Cloudflare";
import { Effect, Layer } from "effect";
import { AuthSchema, AuthSchemaProvider } from "@thomasfosterau/effect-auth-alchemy";

const db = await getBoundD1Database();

export default Alchemy.Stack(
  "api",
  {
    // Mount the provider with the binding it should reconcile, so the engine
    // can drive the resource's lifecycle.
    providers: Layer.mergeAll(Cloudflare.providers(), AuthSchemaProvider({ database: db })),
    state: Cloudflare.state(),
  },
  Effect.gen(function* () {
    yield* AuthSchema("auth-schema", { dropOnDelete: false });
  }),
);
```

### Why the binding goes to the provider

Resource props are **persisted state**. Alchemy strips every value that is not
plain data out of them when it commits a row (`Diff.stripUnresolved`:
"persisted resource state must only ever hold plain data"), and `alchemy
destroy` replays that persisted row into the provider's `delete`. A live D1
handle passed as a prop is therefore present on deploy and _gone_ on delete —
`dropOnDelete: true` would fail with `db.prepare is not a function` on a real
teardown. `bindings` is not an escape hatch either: the engine passes `[]` for
it on every `delete`.

So the binding is captured once, when the provider layer is built, and closed
over by every lifecycle handler — exactly how Alchemy's own providers hold
their clients (`Cloudflare.D1.ProviderLocal` captures the local runtime
context; `Drizzle.SchemaProvider` captures `FileSystem`/`Path`). Keep
`AuthSchemaProvider({ database })` registered for destroys as well as deploys:
a destroy that cannot resolve the database it is asked to drop fails with
`UnknownDatabaseError` rather than silently skipping the drop.

### More than one database

Register the bindings by name and let each resource pick one:

```ts
providers: Layer.mergeAll(
  Cloudflare.providers(),
  AuthSchemaProvider({ databases: { primary: primaryDb, tenants: tenantDb } }),
),
```

```ts
// The stack's program:
Effect.gen(function* () {
  yield* AuthSchema("primary-auth", { database: "primary" });
  yield* AuthSchema("tenant-auth", { database: "tenants", dropOnDelete: true });
});
```

`database` in props is the _name_ of a registered binding. Omit it (the
single-database form above) and it defaults to `DEFAULT_DATABASE`, which is
what `AuthSchemaProvider({ database })` registers under.

Outside an Alchemy program — a cold start, a script, a test — call `migrate(db)`
instead:

```ts
import { Effect } from "effect";
import { migrate, type D1Database } from "@thomasfosterau/effect-auth-alchemy";

export const migrateAuth = (db: D1Database) => Effect.runPromise(migrate(db));
```

> `alchemy` is a **required peer dependency**. The resource, provider and
> lifecycle types all come from `alchemy` itself; there is no vendored or
> structural copy of them here.

## Usage in a Worker

```ts
import * as Cloudflare from "alchemy/Cloudflare";
import { Effect } from "effect";
import { HttpServerRequest, HttpServerResponse } from "effect/http";
import * as Auth from "@thomasfosterau/effect-auth";
import * as AuthD1 from "@thomasfosterau/effect-auth-alchemy";

const AuthD1Database = Cloudflare.D1.Database("auth");

// Your auth routes, using effect-auth services over the D1 stores.
const handle = Effect.gen(function* () {
  const request = yield* HttpServerRequest.HttpServerRequest;
  const users = yield* Auth.UserStore;
  const user = yield* users.get(new URL(request.url).searchParams.get("id") ?? "");
  return HttpServerResponse.text(user === null ? "unknown" : user.id);
}).pipe(
  // A store failure is an `AuthError`; answer it rather than leak it.
  Effect.catchTag("AuthError", () =>
    Effect.succeed(HttpServerResponse.text("unavailable", { status: 503 })),
  ),
);

export default Cloudflare.Worker(
  "api",
  { main: import.meta.url },
  Effect.gen(function* () {
    // Bind the database at init; resolve the raw D1 handle per request.
    const client = yield* Cloudflare.D1.QueryDatabase(AuthD1Database);

    return {
      fetch: Effect.gen(function* () {
        const db = yield* client.raw;
        return yield* handle.pipe(Effect.provide(AuthD1.layer(db)));
      }),
    };
  }).pipe(Effect.provide(Cloudflare.D1.QueryDatabaseBinding)),
);
```

## API

- `layer(db): Layer<AuthStores>` — every effect-auth-sql store over a D1 binding (`AuthStores` is that store set).
- `migrate(db): Effect<void, AuthError>` — the effect-auth-sql DDL against a D1 binding.
- `purgeExpired(db): Effect<PurgeExpiredResult, AuthError>` — effect-auth-sql's `purgeExpired` against a D1 binding: deletes the expired magic-link and email-OTP rows. Nothing else deletes them, so call it from a cron trigger's `scheduled` handler.
- `AuthSchema(id, props?)` — the Alchemy resource (`AuthSchemaProps`: `database?`, `dropOnDelete?`; attributes `AuthSchemaAttributes`), type `AUTH_SCHEMA_TYPE`.
- `AuthSchemaProvider(options)` — its provider layer, given `{ database }` or `{ databases: { name: db } }` (`AuthSchemaProviderOptions`); `DEFAULT_DATABASE` is the single-database name.
- `UnknownDatabaseError` — a resource named a database the provider does not hold.
- `authTableNames` — the tables the schema owns, derived from effect-auth-sql's DDL.
- `D1Client` — `make({ db })` / `layer({ db })` (a `SqlClient` over the binding) and the structural `D1Database`, `D1PreparedStatement`, `D1Result` types; `D1Database` is also exported at the root.

## Notes

- **Timestamps** are stored as epoch milliseconds in `BIGINT` columns (SQLite
  treats these as 64-bit `INTEGER`), so dates past 2038 survive the round trip
  on D1 and Postgres alike.
- **`attributes`** and **`transports`** are JSON `TEXT`; **binary values**
  (WebAuthn challenges and public keys) are base64 `TEXT`.
- Token columns store the SHA-256 hash computed by the service layer — the
  database never sees a raw bearer token.
- effect-auth uses `node:crypto`, so run your Worker with the `nodejs_compat`
  flag.

## License

MIT
