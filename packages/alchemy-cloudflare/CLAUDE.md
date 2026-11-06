# @thomasfosterau/effect-auth-alchemy-cloudflare

Cloudflare D1 for effect-auth on Alchemy v2, built on `@alchemy.run/cloudflare`'s D1 services ([ADR-0023](../../docs/adr/0023-alchemy-packages-on-provider-services.md)): a `SqlClient` over the provider's `QueryDatabaseClient` (`D1Client`), the core's `/sql` stores wired to it (`layer(db)`, `migrate(db)`, `purgeExpired(db)`), and the `AuthSchema` Action that applies the `auth_*` schema to a `Cloudflare.D1.Database` on deploy. One of the two Alchemy packages, split per Alchemy provider (ADR-0022); the Postgres one is `packages/alchemy-postgres`.

## Boundary

Archetype **Storage adapter** (`.fallowrc.json` zone `storage-adapters`, which may import `core` and `ladder`). Peers, all through **`catalog:alchemy-peers`**: `alchemy` and `@alchemy.run/cloudflare` at the exact release the applications pin (`2.0.0-beta.85`), and `effect` (`^4.1.0`, its own catalog entry because alchemy beta.85 itself peers `effect ^4.1.0`; it currently equals the programme floor). Depends on `@thomasfosterau/effect-auth`, for its `/sql` subpath. alchemy and its provider are peers, never bundled, vendored or structurally copied.

## Invariants

- **Built on the provider's services, never raw workerd types.** D1 access goes through `Cloudflare.D1.QueryDatabase`'s `QueryDatabaseClient` (`prepare` / `bind` / `all` / `raw` / `batch`); the schema is an Alchemy `Action` over the same client (`Cloudflare.D1.QueryDatabaseLocal` on deploy). Nothing types or fakes a workerd binding outside `testShim.ts`. Runtime imports stay on the light subpaths (`@alchemy.run/cloudflare/D1/QueryDatabase`, `alchemy/Action`, `alchemy/RuntimeContext`), not the `D1` barrel, which loads the deploy-time `Database` provider and its Cloudflare API client into a Worker bundle.
- **No queries and no schema of its own.** Every store, statement and DDL statement comes from the core's `/sql`; `authTableNames` is `/sql`'s, derived from `schemaStatements`. A table change belongs there.
- **A transaction is a `batch()`.** D1 has no interactive transactions. `D1Client`'s transaction connection buffers row-less writes, sends them with the next row-returning statement as one batch, and sends the rest on `COMMIT`; `ROLLBACK` (or `ROLLBACK TO SAVEPOINT`) discards what is still buffered. Atomic between reads, not across one; the README states which store writes that covers. `@alchemy.run/cloudflare`'s `D1/SQL` (over `@effect/sql-d1`, which dies on a transaction) is not used.
- **The `RuntimeContext` is captured once.** The provider's statements need it; `D1Client.make` reads it when the client is built (in a Worker event, a Durable Object call or an Action body) and provides it to every statement, so the `SqlClient` needs nothing.
- **`AuthSchema` has no delete.** An Action runs when its input (the database id and the DDL) changes; removing it leaves the tables, which go with the database. Its type (`effect-auth::D1AuthSchema`) differs from the Postgres package's resource.
- **`AuthSchema.test.ts` is the suite that loads the alchemy engine** and runs as its own task, `test:alchemy`, in CI's separate `alchemy` job ("Alchemy runtime"); `test:unit` and `check`'s `vp test --typecheck` exclude it (`vite.config.ts`). Never skip it. `Storage.test.ts` imports only the provider's `QueryDatabase` module and `RuntimeContext`, not the engine.

## Terms

- **Client** — the provider's `QueryDatabaseClient`, as `Cloudflare.D1.QueryDatabase(database)` binds it; `db` in this package's signatures.
- **Database** — the `Cloudflare.D1.Database` resource that declares the D1 database; `AuthSchema` takes it.
