# @thomasfosterau/effect-auth-drizzle

Storage layers for [`@thomasfosterau/effect-auth`](../effect-auth), built on
[Drizzle ORM](https://orm.drizzle.team) — **PostgreSQL, SQLite and MySQL**.

Implements the three stores every sign-in flow touches:

| effect-auth tag   | Table                     | What it holds                                          |
| ----------------- | ------------------------- | ------------------------------------------------------ |
| `SessionStore`    | `effect_auth_sessions`    | Sessions keyed by the SHA-256 hash of the bearer token |
| `UserStore`       | `effect_auth_users`       | User records and their password hash                   |
| `IdentifierStore` | `effect_auth_identifiers` | Email / username / phone claims, unique per pair       |

This package **stands alone** — it does not wrap
[`@thomasfosterau/effect-auth-sql`](../sql). It speaks drizzle's query builder
directly, so attribute bags and timestamps are round-tripped natively by the
driver instead of being encoded into `TEXT`. If you want a driver-agnostic layer
covering _every_ effect-auth store (OAuth, WebAuthn, rate limits, ...), reach
for the `sql` package instead; use this one when your app already models its
schema in drizzle and you want the auth tables to live in the same migration
pipeline.

## Install

```sh
npm install @thomasfosterau/effect-auth-drizzle drizzle-orm
```

`drizzle-orm` is a peer dependency, as is your driver of choice (`pg`,
`postgres`, `@neondatabase/serverless`, `@electric-sql/pglite`,
`better-sqlite3`, `@libsql/client`, `mysql2`, ...).

## Usage

The package never opens a connection. Build a drizzle handle however you
already do, hand it over as the `DrizzleDatabase` service, and provide the
stores on top of it.

```ts
import { Layer } from "effect";
import { drizzle } from "drizzle-orm/node-postgres";
import { Pool } from "pg";
import * as Drizzle from "@thomasfosterau/effect-auth-drizzle";

const db = drizzle(new Pool({ connectionString: process.env.DATABASE_URL }));

const stores = Drizzle.layer().pipe(Layer.provide(Drizzle.databaseLayer(db)));
```

`Drizzle.databaseLayer(db)` accepts any drizzle PostgreSQL, SQLite or MySQL
handle, including a transaction handle. `Drizzle.layer(tables)` takes the tables
for the matching dialect — it defaults to the PostgreSQL ones:

```ts
Drizzle.layer(); //                     ← Pg.tables
Drizzle.layer(Drizzle.Sqlite.tables);
Drizzle.layer(Drizzle.MySql.tables);
```

Individual stores are available too, all with the same shape — one namespace per
store, each exporting `make` and `layer`, so you can reach for exactly the one
you need:

```ts
Drizzle.SessionStore.layer(); //    Layer<SessionStore, never, DrizzleDatabase>
Drizzle.UserStore.layer(); //       Layer<UserStore, never, DrizzleDatabase>
Drizzle.IdentifierStore.layer(); // Layer<IdentifierStore, never, DrizzleDatabase>
```

…as are the underlying `Effect`s, if you would rather assemble the store objects
yourself: `Drizzle.SessionStore.make()`, `Drizzle.UserStore.make()`,
`Drizzle.IdentifierStore.make()`. Every one of them takes the same optional
`tables` argument.

### The export map

| Export                                            | What it is                                                    |
| ------------------------------------------------- | ------------------------------------------------------------- |
| `layer(tables?)`                                  | All three stores at once                                      |
| `databaseLayer(db)`, `DrizzleDatabase`            | The database seam                                             |
| `SessionStore`, `UserStore`, `IdentifierStore`    | One namespace per store: `make`, `layer`, requests, resolvers |
| `Requests`                                        | The batched read interface                                    |
| `Pg`, `Sqlite`, `MySql`                           | One namespace per dialect: tables and DDL                     |
| `TableNames`, `defaultTableNames`, `Tables`, rows | What the three dialects agree on                              |

## Dialects

One store implementation serves all three dialects. The fragment of drizzle's
query builder the stores use — `insert().values()`,
`select().from().where().limit()/.orderBy()`, `update().set().where()`,
`delete().where()`, each terminated by `.execute()` — is spelled identically by
`PgDatabase`, `BaseSQLiteDatabase` and `MySqlDatabase`, so `AuthDatabase`
describes exactly that fragment and nothing more. Row and insert types are still
derived from whichever table you pass; there is no `any` in the public surface.

Two consequences worth knowing:

- **No `RETURNING`.** MySQL has no `RETURNING` clause, so
  `IdentifierStore.setVerified` issues an `UPDATE` and then re-reads the row —
  two statements on every dialect rather than a per-dialect branch.
- **Pair the handle with its own tables.** `databaseLayer(db)` and
  `layer(tables)` are separate layers, so nothing stops you handing a
  PostgreSQL handle the SQLite tables. Don't.

| Dialect        | Tables           | Instants             | Attribute bags     | Booleans      |
| -------------- | ---------------- | -------------------- | ------------------ | ------------- |
| **PostgreSQL** | `Drizzle.Pg`     | `timestamptz`        | `jsonb`            | `boolean`     |
| **SQLite**     | `Drizzle.Sqlite` | `integer` (epoch ms) | `text` (JSON mode) | `integer` 0/1 |
| **MySQL**      | `Drizzle.MySql`  | `datetime(3)`        | `json`             | `tinyint` 0/1 |

Column names are identical across the three, and every one of them round-trips
to the same TypeScript values: `string`, `Date`, `Record<string, unknown>`,
`boolean`. MySQL uses `varchar(255)` where the others use `text`, because InnoDB
cannot index a `TEXT` column without a prefix length and the `(type, value)`
unique index has to be indexable.

### Support status

| Dialect        | Status                                                          |
| -------------- | --------------------------------------------------------------- |
| **PostgreSQL** | Covered end-to-end by the PGlite suites (the reference dialect) |
| **SQLite**     | Covered end-to-end by a `better-sqlite3` suite                  |
| **MySQL**      | No server available to the test suite — see below               |

MySQL is exercised through `drizzle-orm/mysql-proxy`, a genuine `MySqlDatabase`
that compiles the store's calls to real MySQL SQL and hands the statement to a
callback rather than a socket. The suite asserts the statements and bound
parameters a server would receive, and the rows the store maps back out of the
driver's wire shape, plus type-level checks that MySQL's tables and rows are
interchangeable with PostgreSQL's. What it cannot check is the server's own
behaviour — that a duplicate `(type, value)` really is rejected, for instance;
the PostgreSQL and SQLite suites cover the store's reaction to that on engines
that are available.

## Batched reads: the `Request` interface

The stores above implement effect-auth's service contracts: one call, one
query. That is the right shape for the auth flows themselves, which read one
session or one user at a time.

Application code often has the opposite shape — a page that resolves twenty
users, or a list that asks "does this identifier exist?" once per row. For
that, the same five read paths are also exposed as Effect `Request`s backed by
`RequestResolver`s, so concurrent lookups collapse into a single
`WHERE ... IN (...)` query:

```ts
import { Effect, Layer } from "effect";
import * as Drizzle from "@thomasfosterau/effect-auth-drizzle";

const requests = Drizzle.Requests.layer().pipe(Layer.provide(Drizzle.databaseLayer(db)));

const program = Effect.forEach(userIds, Drizzle.Requests.getUser, { concurrency: "unbounded" });
//    ^ one SELECT ... WHERE id IN (...), however many ids

program.pipe(Effect.provide(requests));
```

| Constructor                                  | Request                 | Resolves to                      |
| -------------------------------------------- | ----------------------- | -------------------------------- |
| `Requests.getSession(id)`                    | `GetSession`            | `Session \| null`                |
| `Requests.getUser(id)`                       | `GetUser`               | `User \| null`                   |
| `Requests.getUserCredentials(id)`            | `GetUserCredentials`    | `string \| null` (password hash) |
| `Requests.getIdentifierByValue(type, value)` | `GetIdentifierByValue`  | `Identifier \| null`             |
| `Requests.listIdentifiersByUser(userId)`     | `ListIdentifiersByUser` | `ReadonlyArray<Identifier>`      |

Each returns an `Effect<…, AuthError, AuthRequests>`; provide
`Drizzle.Requests.layer()` (on top of a `DrizzleDatabase` layer) to satisfy it.

What the resolvers do inside a batch:

- **De-duplicate.** Twenty concurrent `getUser("u1")` are one row read, not
  twenty.
- **Coalesce.** Different ids in the same batch become one
  `WHERE id IN (...)`.
- **Share a row.** `getUser` and `getUserCredentials` read the same row, so
  they share a resolver and therefore a single query.
- **Group composite keys.** `(type, value)` pairs are grouped by type and
  `OR`-ed together — still one round trip when a batch mixes emails, usernames
  and phone numbers.
- **Keep the store semantics.** A miss is `null`, a user with no identifiers is
  `[]`, `listIdentifiersByUser` stays ordered by `createdAt` ascending, and
  driver failures are the same `AuthError`.

### Which one do I use?

- **The stores** (`layer()`, `SessionStore.layer()`, …) whenever effect-auth
  itself is doing the reading. They are the `SessionStore` / `UserStore` /
  `IdentifierStore` contracts, and **the contracts still use the direct
  implementations** — providing `Requests.layer()` does not change how
  effect-auth reads. Auth decisions want the freshest possible row and a
  predictable single query, not a batch window.
- **The `Request` interface** (`Requests.layer()`, `Requests.getUser`, …) for
  application-side reads, where the same lookup fans out across a request
  handler, a resolver graph, or a page render.

The two are independent layers: provide either, or both.

Two caveats. Effect batches per **resolver instance**, so the resolvers must be
shared — that is what `Requests.layer()` is for; building resolvers per call
site (via `SessionStore.makeResolver()` and friends) batches nothing. And there
is no cache by default: results live only for the batch window. Wrap a resolver
with `RequestResolver.withCache` if you want request-level memoization,
remembering that a cached auth read is a stale auth read.

## Schema

Each dialect namespace exports `sessionsTable`, `usersTable` and
`identifiersTable` — ordinary drizzle schema objects. Re-export them from your
`schema.ts` and `drizzle-kit` will generate migrations for them alongside your
own tables:

```ts
import { Pg } from "@thomasfosterau/effect-auth-drizzle";

export const { sessionsTable, usersTable, identifiersTable } = Pg;
```

Note what is **not** in `effect_auth_users`: there are no `email` or
`email_verified` columns. Since effect-auth's surrogate-key migration, login
handles live exclusively in `effect_auth_identifiers`, so a user may hold
several emails, a username and a phone number, or none at all (passkey-only,
anonymous, or agent users).

`effect_auth_identifiers` is unique on `(type, value)`. That index _is_ the
claim mechanism behind `Auth.claimIdentifier`.

### Custom table names

`defineTables` builds the same three tables under names you choose; every
factory takes the result:

```ts
const tables = Drizzle.Pg.defineTables({ sessions: "app_sessions" });

const stores = Drizzle.layer(tables).pipe(Layer.provide(Drizzle.databaseLayer(db)));
```

Omitted names keep their `effect_auth_*` defaults, and `Sqlite.defineTables` /
`MySql.defineTables` take exactly the same argument.

### SQL migration

If you do not run `drizzle-kit`, the equivalent DDL is exported as data:
`migrationStatements(names?)` returns one statement per entry (safe to replay on
every deploy), and `migrationSql(names?)` joins them into a single script — once
per dialect. Verbatim, under the default names:

```sql
-- Drizzle.Pg.migrationSql()
CREATE TABLE IF NOT EXISTS effect_auth_users (
  id TEXT PRIMARY KEY,
  name TEXT,
  image TEXT,
  password_hash TEXT,
  attributes JSONB NOT NULL DEFAULT '{}'::jsonb,
  created_at TIMESTAMPTZ NOT NULL,
  updated_at TIMESTAMPTZ NOT NULL
);

CREATE TABLE IF NOT EXISTS effect_auth_sessions (
  id TEXT PRIMARY KEY,
  user_id TEXT NOT NULL,
  expires_at TIMESTAMPTZ NOT NULL,
  created_at TIMESTAMPTZ NOT NULL,
  last_activity_at TIMESTAMPTZ NOT NULL,
  attributes JSONB NOT NULL DEFAULT '{}'::jsonb
);

CREATE INDEX IF NOT EXISTS effect_auth_sessions_user_id_idx ON effect_auth_sessions (user_id);

CREATE TABLE IF NOT EXISTS effect_auth_identifiers (
  id TEXT PRIMARY KEY,
  user_id TEXT NOT NULL,
  type TEXT NOT NULL,
  value TEXT NOT NULL,
  verified BOOLEAN NOT NULL DEFAULT FALSE,
  verified_at TIMESTAMPTZ,
  created_at TIMESTAMPTZ NOT NULL
);

CREATE UNIQUE INDEX IF NOT EXISTS effect_auth_identifiers_type_value_key ON effect_auth_identifiers (type, value);

CREATE INDEX IF NOT EXISTS effect_auth_identifiers_user_id_idx ON effect_auth_identifiers (user_id);
```

```sql
-- Drizzle.Sqlite.migrationSql() — same six statements, SQLite's types
CREATE TABLE IF NOT EXISTS effect_auth_sessions (
  id TEXT PRIMARY KEY,
  user_id TEXT NOT NULL,
  expires_at INTEGER NOT NULL,
  created_at INTEGER NOT NULL,
  last_activity_at INTEGER NOT NULL,
  attributes TEXT NOT NULL DEFAULT '{}'
);
```

```sql
-- Drizzle.MySql.migrationSql() — three statements: MySQL has no
-- CREATE INDEX IF NOT EXISTS, so the indexes are declared inline
CREATE TABLE IF NOT EXISTS effect_auth_identifiers (
  id VARCHAR(255) NOT NULL PRIMARY KEY,
  user_id VARCHAR(255) NOT NULL,
  type VARCHAR(32) NOT NULL,
  value VARCHAR(255) NOT NULL,
  verified TINYINT NOT NULL DEFAULT 0,
  verified_at DATETIME(3),
  created_at DATETIME(3) NOT NULL,
  UNIQUE KEY effect_auth_identifiers_type_value_key (type, value),
  KEY effect_auth_identifiers_user_id_idx (user_id)
);
```

## Store semantics

The stores implement effect-auth's contracts exactly:

- **`null` on a miss.** `get`, `getCredentials`, `getByValue` and `setVerified`
  return `null` rather than failing when there is no matching row.
- **Deletes are no-ops** when the row does not exist.
- **Driver failures become `AuthError`** with the original error preserved as
  `cause` — including the unique-index violation raised when two users race for
  the same `(type, value)`. `Auth.claimIdentifier` in core re-reads the pair on
  failure and turns that race into an `IdentifierTakenError`.
- **`getCredentials` reads `password_hash`.** Writing it is the job of a store
  this package does not implement yet (`EmailPasswordStore`), so pair it with
  the `sql` package or your own writer for sign-up flows.
- **Session ids are token hashes.** The service layer hashes the bearer token
  before it reaches the store; the database never sees a raw token.

Stores beyond these three — OAuth accounts, WebAuthn credentials, rate limits,
and the rest — are not covered here yet.

## Tests

The PostgreSQL suites run against
[PGlite](https://github.com/electric-sql/pglite) (PostgreSQL compiled to
WebAssembly, in-process, no server), so `jsonb`, `timestamptz` and unique-index
violations behave exactly as they do in production. The SQLite suite runs the
same assertions against `better-sqlite3` — which also puts drizzle's
_synchronous_ result kind through the seam. `Requests.test.ts` counts the SQL a
program emits through drizzle's own `logger` hook to prove the batching claims
above, and `MySqlSchema.test.ts` pins the MySQL SQL through the proxy driver.

```sh
pnpm run test
```

## License

MIT
