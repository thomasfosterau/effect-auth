# Alchemy packages are built on the provider's services

`@thomasfosterau/effect-auth-alchemy-cloudflare` was split out in [ADR-0022](0022-package-boundaries.md)
peering on `@alchemy.run/cloudflare`, but it imported nothing from it. It kept a structural
`D1Database` type (the part of workerd's binding its client called), a `SqlClient` over that
type, and an `AuthSchema` resource whose provider was handed a live binding when the stack's
providers were built. Two reasons were given: `@alchemy.run/cloudflare` types its binding with
`@cloudflare/workers-types`, a development dependency of its own, and the provider's `D1/SQL`
module wraps `@effect/sql-d1`, whose client dies on `sql.withTransaction`, which four
`@thomasfosterau/effect-auth/sql` stores call.

Neither stops the package being written against the provider. The provider's Effect-native D1
client, `Cloudflare.D1.QueryDatabase(database)`, is what an Alchemy Worker binds; it offers
`prepare` / `bind` / `all` / `raw` and `batch`, and `batch` is the one atomic primitive D1 has.
And a deploy process holds no live D1 binding at all: deploy-time database work goes through
`Cloudflare.D1.QueryDatabaseLocal`, the same client over the Cloudflare HTTP API (or the local
simulator under `alchemy dev`), from an Alchemy `Action`. legation made the same move for its
Cloudflare adapter (legation's ADR-0034).

## Decision

The owner's decision (2026-11-06): **an Alchemy package is built on its provider's services and
resources, never on raw workerd types or structural copies of them.** For
`effect-auth-alchemy-cloudflare`:

- **Data access runs on `Cloudflare.D1.QueryDatabase`.** `D1Client` is a `SqlClient` over the
  `QueryDatabaseClient` it binds, capturing the event's `RuntimeContext`; `layer`, `migrate` and
  `purgeExpired` take that client. The structural `D1Database` type is gone.
- **A transaction is a `batch()`.** D1 has no interactive transactions, so `D1Client` buffers a
  transaction's row-less writes and sends them, with the next statement that returns rows, as one
  batch; `COMMIT` sends the rest. Writes between two reads commit together; what was sent before a
  read stays committed if a later batch fails. `@effect/sql-d1` (the provider's `D1/SQL`) stays
  unused, because it dies on a transaction.
- **The schema is an Alchemy `Action`, not a custom resource.** `AuthSchema(id, database)` binds a
  `Cloudflare.D1.Database` with `QueryDatabase` in the Action's init and applies
  `@thomasfosterau/effect-auth/sql`'s DDL in its body; the application provides
  `Cloudflare.D1.QueryDatabaseLocal`. The type id stays `effect-auth::D1AuthSchema`. The database
  resource's own `migrations` is not used: it reads one directory of `.sql` files, which the
  application's migrations occupy, and the auth DDL is code shared with Postgres.

## Consequences

- `AuthSchemaProvider`, `AuthSchemaProps`, `DEFAULT_DATABASE`, `UnknownDatabaseError` and
  `dropOnDelete` are gone. An Action has no delete: removing or destroying `AuthSchema` leaves the
  tables, which go with the `Cloudflare.D1.Database` when it is destroyed.
- The schema is applied when the Action's input (the database id and the DDL) changes, not on
  every deploy; `alchemy deploy --force` re-runs it.
- The package's tests stub at the provider's seams: the provider's `PreparedStatement` over an
  in-memory SQLite fake of the raw binding, a stub `QueryDatabase` that resolves a database's id
  as `QueryDatabaseLocal` does, and a stub `Cloudflare.D1.Database` provider under the real
  Alchemy engine.
- `effect-auth-alchemy-postgres` is unchanged: no `@alchemy.run/*` provider gives it a Postgres
  client to build on (ADR-0022, rule 2).
