# @thomasfosterau/effect-auth-alchemy-postgres

**Postgres** support for [`@thomasfosterau/effect-auth`](https://github.com/thomasfosterau/effect-auth/tree/trunk/packages/effect-auth) on
[Alchemy v2](https://v2.alchemy.run), covering both sides of the deploy:

- **Provider side** — the `AuthSchema` resource, so the Alchemy engine keeps
  the auth schema reconciled in a Postgres database on every deploy.
- **Consumer side** — `layer(source)`, which turns a Cloudflare Hyperdrive
  binding (or a Postgres URL) into every effect-auth store.

It is the Postgres counterpart of
[`@thomasfosterau/effect-auth-alchemy-cloudflare`](https://github.com/thomasfosterau/effect-auth/tree/trunk/packages/alchemy-cloudflare)
(D1). Its `AuthSchema` is an Alchemy Action over the D1 provider's
`QueryDatabase` (`effect-auth::D1AuthSchema`), this one a resource of its own
type (`effect-auth::PostgresAuthSchema`), so one stack can declare both. Every store, statement and DDL comes from the core's
[`/sql` subpath](https://github.com/thomasfosterau/effect-auth/blob/trunk/docs/guides/storage.md#sql-storage-sql).

The package is named for the database, not for an Alchemy provider: the
Postgres server can live anywhere (PlanetScale, Neon, RDS, your own), and
nothing here depends on how it is hosted. A PlanetScale `PostgresRole`'s
`connectionUrl` is a `Redacted<string>` that `database(url)` takes as it is.

## Install

```sh
pnpm add @thomasfosterau/effect-auth-alchemy-postgres @thomasfosterau/effect-auth effect alchemy@2.0.0-beta.85 @effect/sql-pg
```

## Usage

In the Worker, provide every store over the Hyperdrive binding. Hyperdrive
pools at the edge, so keep the client's own pool small:

```ts
import * as Postgres from "@thomasfosterau/effect-auth-alchemy-postgres";

const stores = Postgres.Postgres.layer(env.HYPERDRIVE, { maxConnections: 1 });
```

## Entry points

- `layer(source, options?)`, `migrate(source, options?)`, `purgeExpired(source, options?)`, `clientLayer(source, options?)` — over a `Hyperdrive` binding (`{ connectionString }`) or a `Redacted` URL (`Source`); `options` (`ClientOptions`) are `@effect/sql-pg`'s pool settings. `AuthStores` is the store set `layer` provides.
- `database(url, options?)` — the `AuthSchema` target, reached by URL.
- `AuthSchema(id, props?)` — the Alchemy resource (`AuthSchemaProps`: `database?`, `dropOnDelete?`; attributes `AuthSchemaAttributes`), type `AUTH_SCHEMA_TYPE` (`effect-auth::PostgresAuthSchema`).
- `AuthSchemaProvider(options)` — its provider layer, given `{ database }` or `{ databases: { name: db } }` (`AuthSchemaProviderOptions`); `DEFAULT_DATABASE` is the single-database name.
- `PostgresDatabase` / `postgresDatabase(clientLayer)` / `AuthSchemaDatabase` — a target over any Postgres `SqlClient` layer.
- `UnknownDatabaseError` — a resource named a database the provider does not hold.
- `authTableNames` — the tables the schema owns, derived from `/sql`'s DDL.

## Guides

- [Storage on Alchemy](https://github.com/thomasfosterau/effect-auth/blob/trunk/docs/guides/alchemy.md): the peers, `AuthSchema` and its provider, and the storage format.
- [Auth as an internal Worker on Alchemy](https://github.com/thomasfosterau/effect-auth/blob/trunk/docs/guides/alchemy-internal-worker.md).

## License

MIT
