# @thomasfosterau/effect-auth-alchemy

Cloudflare **D1** support for [`@thomasfosterau/effect-auth`](../effect-auth) on
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
| `D1Client`   | A `SqlClient` (from `effect/unstable/sql`) over a D1 binding.         |
| `Storage`    | `layer(db)` / `migrate(db)` — the client wired to the SQL stores.     |
| `AuthSchema` | The Alchemy resource + provider that reconciles the schema on deploy. |

Every store, statement and DDL comes from
[`@thomasfosterau/effect-auth-sql`](../sql), which implements the effect-auth
storage interfaces against `SqlClient` and is shared with every other SQL
deployment. D1 is SQLite, so the same tables and the same queries apply.

## Storage layers

```ts
import { Effect, Layer } from "effect";
import * as Auth from "@thomasfosterau/effect-auth";
import * as AuthD1 from "@thomasfosterau/effect-auth-alchemy";

const AppLayer = (db: AuthD1.D1Database) =>
  Auth.SessionManagerLayer(sessionConfig).pipe(Layer.provideMerge(AuthD1.layer(db)));
```

`AuthD1.layer(db)` provides every store `@thomasfosterau/effect-auth-sql`
implements — `SessionStore`, `UserStore`, `EmailPasswordStore`, `RoleStore`,
`RateLimitStore`, `EmailVerificationStore`, `ChallengeStore`, `CredentialStore`,
`OAuthStateStore`, `OAuthAccountStore`, `PasswordResetStore`, `MagicLinkStore`,
`EmailOtpStore`, `MultiFactorStore`, `IdentifierStore`, … — all backed by
`auth_`-prefixed tables so they coexist with your application's own schema.

For a subset, provide `D1Client.layer({ db })` and pick the per-store layers
from `@thomasfosterau/effect-auth-sql` directly:

```ts
import * as Sql from "@thomasfosterau/effect-auth-sql";
import { D1Client } from "@thomasfosterau/effect-auth-alchemy";

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
answers those control statements locally instead of sending them, so the three
stores that ask for a transaction (`ChallengeStore.create`,
`OAuthStateStore.create`, `EmailOtpStore.upsert` — each a `DELETE` followed by
an `INSERT`) run as autocommitted statements rather than failing. **Multi-step
writes are not atomic on D1.** Everything that needs atomicity is already a
single statement (`ON CONFLICT … DO UPDATE`, `UPDATE … RETURNING`).

## The `AuthSchema` resource

`AuthSchema` keeps the effect-auth tables (`auth_users`, `auth_sessions`,
`auth_oauth_accounts`, …) reconciled inside a D1 database on every deploy.

- **Idempotent** — the DDL is all `CREATE TABLE IF NOT EXISTS`, so reconciling
  is cheap to repeat and additive schema changes from a library upgrade are
  picked up automatically.
- **Owns the schema, not the database** — the database is passed in as a
  binding, so tearing the stack down never destroys auth data unless you opt in
  with `dropOnDelete: true`.

It is built with Alchemy's own `Resource` constructor, and `AuthSchemaProvider()`
with Alchemy's own `Provider.succeed` — the same primitives `Alchemy.Random` and
`Cloudflare.D1.Database` are built from. The **engine** runs the lifecycle
(`read` → `diff` → `reconcile` / `delete`); nothing here re-implements it.

```ts
import * as Alchemy from "alchemy";
import * as Cloudflare from "alchemy/Cloudflare";
import { Effect, Layer } from "effect";
import { AuthSchema, AuthSchemaProvider } from "@thomasfosterau/effect-auth-alchemy";

export default Alchemy.Stack(
  "api",
  {
    // Mount the provider so the engine can drive the resource's lifecycle.
    providers: Layer.mergeAll(Cloudflare.providers(), AuthSchemaProvider()),
    state: Cloudflare.state(),
  },
  Effect.gen(function* () {
    const db = yield* getBoundD1Database();
    yield* AuthSchema("auth-schema", { database: db });
  }),
);
```

Outside an Alchemy program — a cold start, a script, a test — call `migrate(db)`
instead:

```ts
import { Effect } from "effect";
import { migrate } from "@thomasfosterau/effect-auth-alchemy";

await Effect.runPromise(migrate(db));
```

> `alchemy` is a **required peer dependency**. The resource, provider and
> lifecycle types all come from `alchemy` itself; there is no vendored or
> structural copy of them here.

## Installation

```sh
bun add @thomasfosterau/effect-auth-alchemy @thomasfosterau/effect-auth effect alchemy
```

`alchemy` and `effect` are required peer dependencies;
`@thomasfosterau/effect-auth-sql` comes along as a dependency.

## Usage in a Worker

```ts
import * as Cloudflare from "alchemy/Cloudflare";
import { Effect } from "effect";
import { HttpServerRequest, HttpServerResponse } from "effect/unstable/http";
import * as AuthD1 from "@thomasfosterau/effect-auth-alchemy";

const AuthD1Database = Cloudflare.D1.Database("auth");

export default Cloudflare.Worker(
  "api",
  Effect.gen(function* () {
    // Bind the database, then take the raw D1 handle the stores need.
    const client = yield* Cloudflare.D1.QueryDatabase(AuthD1Database);
    const db = yield* client.raw;

    return {
      fetch: Effect.gen(function* () {
        const request = yield* HttpServerRequest.HttpServerRequest;
        // ... your auth routes, using effect-auth services ...
        return HttpServerResponse.text("ok");
      }).pipe(Effect.provide(AuthD1.layer(db))),
    };
  }),
);
```

## Notes

- **Timestamps** are stored as epoch milliseconds in `BIGINT` columns (SQLite
  treats these as 64-bit `INTEGER`), so dates past 2038 survive the round trip
  on D1, Postgres and MySQL alike.
- **`attributes`** and **`transports`** are JSON `TEXT`; **binary values**
  (WebAuthn challenges and public keys) are base64 `TEXT`.
- Token columns store the SHA-256 hash computed by the service layer — the
  database never sees a raw bearer token.
- effect-auth uses `node:crypto`, so run your Worker with the `nodejs_compat`
  flag.
