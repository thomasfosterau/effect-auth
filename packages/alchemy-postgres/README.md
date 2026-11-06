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
[`/sql` subpath](https://github.com/thomasfosterau/effect-auth/tree/trunk/packages/effect-auth#sql-storage-sql).

The package is named for the database, not for an Alchemy provider: the
Postgres server can live anywhere (PlanetScale, Neon, RDS, your own), and
nothing here depends on how it is hosted. A PlanetScale `PostgresRole`'s
`connectionUrl` is a `Redacted<string>` that `database(url)` takes as it is.

## Install

```sh
pnpm add @thomasfosterau/effect-auth-alchemy-postgres @thomasfosterau/effect-auth effect alchemy@2.0.0-beta.85 @effect/sql-pg
```

`alchemy` (exactly `2.0.0-beta.85`, the release the effect-auth applications
pin), `@effect/sql-pg` (`^4.1.0`) and `effect` (`^4.1.0`) are required peer
dependencies. `@thomasfosterau/effect-auth` comes along as a dependency, for
its `/sql` subpath.

In the Worker, provide every store over the Hyperdrive binding. Hyperdrive
pools at the edge, so keep the client's own pool small:

```ts
import * as Postgres from "@thomasfosterau/effect-auth-alchemy-postgres";

const stores = Postgres.layer(env.HYPERDRIVE, { maxConnections: 1 });
```

`@effect/sql-pg` connects with `node:net` / `node:tls`: the Worker needs the
`nodejs_compat` flag.

On deploy, `AuthSchema` reconciles the Postgres database. A Hyperdrive binding
only exists inside a Worker, so the provider reaches the origin database by
URL:

```ts
import * as Postgres from "@thomasfosterau/effect-auth-alchemy-postgres";

const providers = Postgres.AuthSchemaProvider({
  database: Postgres.database(Redacted.make(process.env.DATABASE_URL)),
});
// in the program:
yield * Postgres.AuthSchema("auth-schema");
```

Several databases register by name (`AuthSchemaProvider({ databases })`), and
each resource picks one with its `database` prop, as in the D1 package. The
database is held by the provider, never passed in props: props are persisted
state, and a destroy replays them. Tables are dropped only with
`dropOnDelete: true`, and a destroy that cannot resolve its database fails with
`UnknownDatabaseError`. The full recipe, including deploying auth
as an internal-only Worker, is the
[Auth as an internal Worker on Alchemy](https://github.com/thomasfosterau/effect-auth/blob/trunk/docs/guides/alchemy-internal-worker.md)
guide.

## API

- `layer(source, options?)`, `migrate(source, options?)`, `purgeExpired(source, options?)`, `clientLayer(source, options?)` — over a `Hyperdrive` binding (`{ connectionString }`) or a `Redacted` URL (`Source`); `options` (`ClientOptions`) are `@effect/sql-pg`'s pool settings. `AuthStores` is the store set `layer` provides.
- `database(url, options?)` — the `AuthSchema` target, reached by URL.
- `AuthSchema(id, props?)` — the Alchemy resource (`AuthSchemaProps`: `database?`, `dropOnDelete?`; attributes `AuthSchemaAttributes`), type `AUTH_SCHEMA_TYPE` (`effect-auth::PostgresAuthSchema`).
- `AuthSchemaProvider(options)` — its provider layer, given `{ database }` or `{ databases: { name: db } }` (`AuthSchemaProviderOptions`); `DEFAULT_DATABASE` is the single-database name.
- `PostgresDatabase` / `postgresDatabase(clientLayer)` / `AuthSchemaDatabase` — a target over any Postgres `SqlClient` layer.
- `UnknownDatabaseError` — a resource named a database the provider does not hold.
- `authTableNames` — the tables the schema owns, derived from `/sql`'s DDL.

## Notes

- **Timestamps** are stored as epoch milliseconds in `BIGINT` columns, so
  dates past 2038 survive the round trip.
- Token columns store the SHA-256 hash computed by the service layer — the
  database never sees a raw bearer token.

## License

MIT
