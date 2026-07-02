# @effect-auth/sql

Driver-agnostic SQL storage layers for [`effect-auth`](../effect-auth), built
on `effect/unstable/sql`'s `SqlClient`.

Every effect-auth storage interface — sessions, users, email/password,
password resets, email verification, OAuth (state/accounts/users), WebAuthn
(challenges/credentials), magic links, email OTPs, two-factor (records +
pending challenges), rate limits and roles — is implemented against the
`SqlClient` service, so it works with **any** `SqlClient` layer: Postgres,
MySQL, SQLite, Cloudflare D1, etc. No ORM, no dialect lock-in.

## Usage

```ts
import { Effect, Layer } from "effect";
import * as Sql from "@effect-auth/sql";

// Any Layer that provides SqlClient.SqlClient (pg, mysql, sqlite, D1, ...).
declare const SqlClientLayer: Layer.Layer<import("effect/unstable/sql").SqlClient.SqlClient>;

// 1. Create the schema (idempotent — safe to run on every deploy).
await Effect.runPromise(Sql.migrate.pipe(Effect.provide(SqlClientLayer)));

// 2. Provide every effect-auth store in one go.
const AuthStores = Sql.layer.pipe(Layer.provide(SqlClientLayer));
```

Individual layers (`Sql.SessionStoreLayer`, `Sql.RateLimitStoreLayer`, ...)
and store constructors (`Sql.makeSessionStore`, ...) are also exported when
you only need a subset, or want to mix backends (e.g. keep ephemeral stores in
`effect-auth`'s KeyValueStore-backed layers and persistent data in SQL).

## Schema

Tables are namespaced with an `auth_` prefix (`auth_users`, `auth_sessions`,
`auth_oauth_accounts`, ...) so they can live alongside your own tables.
`Sql.schemaStatements` exposes the raw DDL; `Sql.migrate` executes it through
the ambient `SqlClient`. Every statement uses `CREATE TABLE IF NOT EXISTS`, so
repeated runs are no-ops.

Column types are limited to `TEXT`/`INTEGER` for dialect portability, using
the same data codecs as `@effect-auth/alchemy`:

- dates: epoch milliseconds (`INTEGER`)
- booleans: `0`/`1` (`INTEGER`)
- attribute bags / arrays: JSON (`TEXT`)
- binary values (WebAuthn keys, challenges): base64 (`TEXT`)

## Notes

- **Error mapping** — driver failures surface as effect-auth's `AuthError`
  (or die for read paths whose interfaces don't admit storage errors).
  `RoleStore` fails closed: storage errors become defects, never empty
  grants.
- **Upserts** — implemented as portable select-then-update/insert rather than
  dialect-specific `ON CONFLICT` clauses, so they are not atomic under
  concurrent writers. That's acceptable for these auth flows (single-owner
  tokens, best-effort counters); wrap calls in `sql.withTransaction` if your
  driver needs stronger guarantees.

## Testing

The test suite builds a real `SqlClient` (via `SqlClient.make` +
`Statement.makeCompilerSqlite`) over an in-memory `better-sqlite3` database,
exercising the stores through the genuine tagged-template/compiler pipeline.
