# @thomasfosterau/effect-auth-alchemy-postgres

Postgres for effect-auth on Alchemy v2: an `@effect/sql-pg` `SqlClient` from a Cloudflare Hyperdrive binding or a URL, the core's `/sql` stores wired to it (`layer(source)`, `migrate`, `purgeExpired`), and the `AuthSchema` resource with its provider that reconciles the `auth_*` schema in Postgres on deploy. The Postgres half of the former `effect-auth-alchemy`; the D1 half is `packages/alchemy-cloudflare`.

## Boundary

Archetype **Storage adapter** (`.fallowrc.json` zone `storage-adapters`, which may import `core` and `ladder`). Peers, all through **`catalog:alchemy-peers`**: `alchemy` (exactly `2.0.0-beta.85`, the applications' pin), `@effect/sql-pg` (`^4.1.0`) and `effect` (`^4.1.0`). Depends on `@thomasfosterau/effect-auth`, for its `/sql` subpath.

**Named for the database, not for an Alchemy provider** (ADR-0022). The owner's rule splits the Alchemy packages per provider and named this half for `@alchemy.run/planetscale`, but nothing here can depend on that provider: the code is host-agnostic Postgres. The provider is built before any resource exists, so a PlanetScale `PostgresRole`'s outputs cannot reach it; the role's `connectionUrl` is already a `Redacted<string>` that `database(url)` takes unchanged, and its `PostgresOrigin` is a connection shape the code has no use for. So it peers on no `@alchemy.run/*` package.

## Invariants

- **No queries and no schema of its own.** Every store, statement and DDL statement comes from the core's `/sql`; `authTableNames` is `/sql`'s.
- **`AuthSchema.test.ts` loads the alchemy runtime** and runs only in `test:alchemy` (CI's `alchemy` job), with `Postgres.test.ts`, whose cases need a server (`DATABASE_URL`; the CI job runs a Postgres service). `test:unit` runs neither (`--passWithNoTests`); `check`'s `vp test --typecheck` excludes the alchemy suite. Never skip them. The `AuthSchema` cases run on PGlite; the case against a real server runs where `DATABASE_URL` is set.
- **The database goes to the provider, never into resource props.** `AuthSchemaProvider({ database | databases })` captures each `PostgresDatabase` (a `SqlClient` layer, built per lifecycle operation) when the layer is built. A destroy that cannot resolve its database fails with `UnknownDatabaseError`.
- **The resource owns the schema, not the database.** Reconcile is idempotent `CREATE … IF NOT EXISTS`; tables are dropped only with `dropOnDelete: true`. Its type (`effect-auth::PostgresAuthSchema`) differs from the D1 package's, so a stack can mount both providers.
- **`Hyperdrive` is structural** (`{ connectionString }`), so `@cloudflare/workers-types`' binding satisfies it without a Cloudflare types dependency. `@effect/sql-pg` opens connections with `node:net` / `node:tls`: a Worker needs `nodejs_compat`.

## Terms

- **Postgres database** — a `PostgresDatabase`: the `SqlClient` layer the provider connects to Postgres with on each lifecycle operation. The deploy-time counterpart of a Hyperdrive binding, which exists only inside a Worker.
- **Source** — a Hyperdrive binding or a `Redacted` URL; what the runtime layers connect to.
