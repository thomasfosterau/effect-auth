# @thomasfosterau/effect-auth-alchemy-cloudflare

Cloudflare D1 for effect-auth on Alchemy v2: a `SqlClient` over a D1 binding (`D1Client`), the core's `/sql` stores wired to it (`layer(db)`, `migrate(db)`, `purgeExpired(db)`), and the `AuthSchema` resource with its provider that reconciles the `auth_*` schema in D1 on deploy. One of the two Alchemy packages, split per Alchemy provider (ADR-0022); the Postgres one is `packages/alchemy-postgres`.

## Boundary

Archetype **Storage adapter** (`.fallowrc.json` zone `storage-adapters`, which may import `core` and `ladder`). Peers, all through **`catalog:alchemy-peers`**: `alchemy` and `@alchemy.run/cloudflare` at the exact release the applications pin (`2.0.0-beta.85`), and `effect` (`^4.1.0`, its own catalog entry because alchemy beta.85 itself peers `effect ^4.1.0`; it currently equals the programme floor). Depends on `@thomasfosterau/effect-auth`, for its `/sql` subpath. alchemy is a peer, never bundled, vendored or structurally copied: the resource, provider and lifecycle types come from `alchemy` itself.

## Invariants

- **No queries and no schema of its own.** Every store, statement and DDL statement comes from the core's `/sql`; `authTableNames` is `/sql`'s, derived from `schemaStatements`. A table change belongs there.
- **`AuthSchema.test.ts` is the only suite that loads the alchemy runtime** and runs as its own task, `test:alchemy`, in CI's separate `alchemy` job ("Alchemy runtime"); `test:unit` and `check`'s `vp test --typecheck` exclude it (`vite.config.ts`). Never skip it. `Storage.test.ts` imports only the alchemy-free `/sql`.
- **D1 has no transactions.** `D1Client` answers `BEGIN` / `COMMIT` / `ROLLBACK` / `SAVEPOINT` locally instead of sending them, so the multi-step store writes run as autocommitted statements: atomicity is per statement only, and the README states which writes that affects. That is also why `@alchemy.run/cloudflare`'s `D1/SQL` (over `@effect/sql-d1`, which dies on a transaction) is not used.
- **The live binding goes to the provider, never into resource props.** Props are persisted state that Alchemy strips of non-plain data and replays into `delete`; `AuthSchemaProvider({ database | databases })` captures the binding when the layer is built. A destroy that cannot resolve its database fails with `UnknownDatabaseError` rather than skipping the drop.
- **The resource owns the schema, not the database.** Reconcile is idempotent `CREATE … IF NOT EXISTS`; tables are dropped only with `dropOnDelete: true`.
- **The engine runs the lifecycle**: `AuthSchema` is built with Alchemy's `Resource` and `AuthSchemaProvider` with `Provider.succeed`; nothing here re-implements `read` / `diff` / `reconcile` / `delete`. Its type (`effect-auth::D1AuthSchema`) differs from the Postgres package's, so a stack can mount both providers.
- **`D1Database` is structural** (just what the client calls). `@alchemy.run/cloudflare` exports no binding type of its own: it types the binding with `@cloudflare/workers-types`, which it lists only as a development dependency, so naming that type here would make it `any` for a consumer without workers-types. `@cloudflare/workers-types`, Miniflare and `Cloudflare.D1.QueryDatabase`'s `raw` handle all satisfy the structural type.

## Terms

- **Binding** — the runtime D1 handle (`D1Database`), as opposed to the `Cloudflare.D1.Database` resource that declares it.
- **Registered database** — a D1 binding named in `AuthSchemaProvider({ databases })`; `AuthSchema`'s `database` prop names one, defaulting to `DEFAULT_DATABASE`.
