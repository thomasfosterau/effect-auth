# @thomasfosterau/effect-auth-alchemy

Cloudflare D1 and Postgres (over Hyperdrive) for effect-auth on Alchemy v2: a `SqlClient` over a D1 binding (`D1Client`), the effect-auth-sql stores wired to it (`layer(db)`, `migrate(db)`), the same over Postgres in the `./postgres` entry (`Postgres.ts`, an `@effect/sql-pg` client from a Hyperdrive binding or URL), and the `AuthSchema` resource with its provider that reconciles the `auth_*` schema on deploy, in D1 or Postgres.

## Boundary

Archetype **Storage adapter** (`.fallowrc.json` zone `storage-adapters`, which may import `core` and `ladder`). Peers: `alchemy` (`catalog:peers`, `>=2.0.0-beta.80`), `@effect/sql-pg` (optional, `catalog:alchemy-peers`, needed only by `./postgres`) and `effect` through **`catalog:alchemy-peers`** (`>=4.0.0`, above the programme floor, because alchemy beta.80 itself peers `effect ^4.0.0`). Depends on `@thomasfosterau/effect-auth` and `@thomasfosterau/effect-auth-sql`. alchemy is a peer, never bundled, vendored or structurally copied: the resource, provider and lifecycle types come from `alchemy` itself.

## Invariants

- **No queries and no schema of its own.** Every store, statement and DDL statement comes from effect-auth-sql; `authTableNames` (`AuthTables.ts`) is derived from `Sql.schemaStatements`. A table change belongs in effect-auth-sql.
- **`AuthSchema.test.ts` is the only suite that loads the alchemy runtime** and runs as its own task, `test:alchemy`, in CI's separate `alchemy` job ("Alchemy runtime"); `test:unit` and `check`'s `vp test --typecheck` exclude it (`vite.config.ts`). Never skip it. `Storage.test.ts` imports only the alchemy-free `AuthTables.ts`. Its Postgres cases run on PGlite; the case against a real server, and `Postgres.test.ts`, run where `DATABASE_URL` is set, which the CI job provides with a Postgres service (`test:alchemy` runs both files).
- **The root entry never imports `@effect/sql-pg`.** Only `Postgres.ts` (the `./postgres` entry) does, so a D1 app never needs the optional peer. `AuthSchema.ts` knows a Postgres database only as a `SqlClient` layer (`PostgresDatabase`).
- **D1 has no transactions.** `D1Client` answers `BEGIN` / `COMMIT` / `ROLLBACK` / `SAVEPOINT` locally instead of sending them, so the multi-step store writes run as autocommitted statements: atomicity is per statement only, and the README states which writes that affects.
- **The live binding goes to the provider, never into resource props.** Props are persisted state that Alchemy strips of non-plain data and replays into `delete`; `AuthSchemaProvider({ database | databases })` captures the binding when the layer is built. A destroy that cannot resolve its database fails with `UnknownDatabaseError` rather than skipping the drop.
- **The resource owns the schema, not the database.** Reconcile is idempotent `CREATE … IF NOT EXISTS`; tables are dropped only with `dropOnDelete: true`.
- **The engine runs the lifecycle**: `AuthSchema` is built with Alchemy's `Resource` and `AuthSchemaProvider` with `Provider.succeed`; nothing here re-implements `read` / `diff` / `reconcile` / `delete`.
- **`D1Database` is structural** (just what the client calls), so `@cloudflare/workers-types`, Miniflare and Alchemy's `QueryDatabase` handle all satisfy it; no Cloudflare types package is a dependency.

## Terms

- **Binding** — the runtime D1 handle (`D1Database`), as opposed to the `Cloudflare.D1.Database` resource that declares it.
- **Postgres database** — a `PostgresDatabase`: the `SqlClient` layer the provider connects to Postgres with on each lifecycle operation. The deploy-time counterpart of a Hyperdrive binding, which exists only inside a Worker.
- **Registered database** — a D1 binding or Postgres database named in `AuthSchemaProvider({ databases })`; `AuthSchema`'s `database` prop names one, defaulting to `DEFAULT_DATABASE`.
