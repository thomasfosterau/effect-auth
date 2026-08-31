# @thomasfosterau/effect-auth-drizzle

PostgreSQL storage layers for
[`@thomasfosterau/effect-auth`](../effect-auth), built on
[Drizzle ORM](https://orm.drizzle.team)'s `drizzle-orm/pg-core`.

Implements the three stores every sign-in flow touches:

| effect-auth tag   | Table                     | What it holds                                          |
| ----------------- | ------------------------- | ------------------------------------------------------ |
| `SessionStore`    | `effect_auth_sessions`    | Sessions keyed by the SHA-256 hash of the bearer token |
| `UserStore`       | `effect_auth_users`       | User records and their password hash                   |
| `IdentifierStore` | `effect_auth_identifiers` | Email / username / phone claims, unique per pair       |

This package **stands alone** — it does not wrap
[`@thomasfosterau/effect-auth-sql`](../sql). It speaks drizzle's PostgreSQL
query builder directly, so `jsonb` attribute bags and `timestamptz` columns are
round-tripped natively by the driver instead of being encoded into `TEXT`. If
you want a driver-agnostic layer covering _every_ effect-auth store (OAuth,
WebAuthn, rate limits, ...), reach for the `sql` package instead; use this one
when your app already models its schema in drizzle and you want the auth tables
to live in the same migration pipeline.

## Install

```sh
npm install @thomasfosterau/effect-auth-drizzle drizzle-orm
```

`drizzle-orm` is a peer dependency, as is your PostgreSQL driver of choice
(`pg`, `postgres`, `@neondatabase/serverless`, `@electric-sql/pglite`, ...).

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

`Drizzle.databaseLayer(db)` is shorthand for
`Layer.succeed(Drizzle.DrizzleDatabase, db)` — any drizzle PostgreSQL handle
(including a transaction handle) is accepted.

Individual stores are available too, all with the same shape — one module per
store, so you can reach for exactly the one you need:

```ts
Drizzle.sessionStoreLayer(); // Layer<SessionStore, never, DrizzleDatabase>
Drizzle.userStoreLayer(); // Layer<UserStore, never, DrizzleDatabase>
Drizzle.identifierStoreLayer(); // Layer<IdentifierStore, never, DrizzleDatabase>
```

…as are the underlying `Effect`s, if you would rather assemble the store
objects yourself: `makeSessionStore()`, `makeUserStore()`,
`makeIdentifierStore()`.

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

const requests = Drizzle.requestsLayer().pipe(Layer.provide(Drizzle.databaseLayer(db)));

const program = Effect.forEach(userIds, Drizzle.getUser, { concurrency: "unbounded" });
//    ^ one SELECT ... WHERE id IN (...), however many ids

program.pipe(Effect.provide(requests));
```

| Constructor                         | Request                 | Resolves to                      |
| ----------------------------------- | ----------------------- | -------------------------------- |
| `getSession(id)`                    | `GetSession`            | `Session \| null`                |
| `getUser(id)`                       | `GetUser`               | `User \| null`                   |
| `getUserCredentials(id)`            | `GetUserCredentials`    | `string \| null` (password hash) |
| `getIdentifierByValue(type, value)` | `GetIdentifierByValue`  | `Identifier \| null`             |
| `listIdentifiersByUser(userId)`     | `ListIdentifiersByUser` | `ReadonlyArray<Identifier>`      |

Each returns an `Effect<…, AuthError, AuthRequests>`; provide
`Drizzle.requestsLayer()` (on top of a `DrizzleDatabase` layer) to satisfy it.

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

- **The stores** (`layer()`, `sessionStoreLayer()`, …) whenever effect-auth
  itself is doing the reading. They are the `SessionStore` / `UserStore` /
  `IdentifierStore` contracts, and **the contracts still use the direct
  implementations** — providing `requestsLayer()` does not change how
  effect-auth reads. Auth decisions want the freshest possible row and a
  predictable single query, not a batch window.
- **The `Request` interface** (`requestsLayer()`, `getUser`, …) for
  application-side reads, where the same lookup fans out across a request
  handler, a resolver graph, or a page render.

The two are independent layers: provide either, or both.

Two caveats. Effect batches per **resolver instance**, so the resolvers must be
shared — that is what `requestsLayer()` is for; building resolvers per call
site (via `makeSessionResolver()` and friends) batches nothing. And there is no
cache by default: results live only for the batch window. Wrap a resolver with
`RequestResolver.withCache` if you want request-level memoization, remembering
that a cached auth read is a stale auth read.

## Schema

`sessionsTable`, `usersTable` and `identifiersTable` are ordinary drizzle
schema objects — export them from your `schema.ts` and `drizzle-kit` will
generate migrations for them alongside your own tables:

```ts
export { sessionsTable, usersTable, identifiersTable } from "@thomasfosterau/effect-auth-drizzle";
```

Conventions:

- Timestamps are `timestamp({ mode: "date", withTimezone: true })`, so the
  domain sees real `Date` values and PostgreSQL stores `timestamptz`.
- Attribute bags are `jsonb().$type<Record<string, unknown>>()`, `NOT NULL`
  with a `'{}'` default.
- `effect_auth_identifiers` is unique on `(type, value)`. That index _is_ the
  claim mechanism behind `Auth.claimIdentifier`.

Note what is **not** in `effect_auth_users`: there are no `email` or
`email_verified` columns. Since effect-auth's surrogate-key migration, login
handles live exclusively in `effect_auth_identifiers`, so a user may hold
several emails, a username and a phone number, or none at all (passkey-only,
anonymous, or agent users).

### Custom table names

`defineTables` builds the same three tables under names you choose; every
factory takes the result:

```ts
const tables = Drizzle.defineTables({ sessions: "app_sessions" });

const stores = Drizzle.layer(tables).pipe(Layer.provide(Drizzle.databaseLayer(db)));
```

Omitted names keep their `effect_auth_*` defaults.

### SQL migration

If you do not run `drizzle-kit`, the equivalent DDL is exported as data:
`Drizzle.migrationStatements(names?)` returns one idempotent statement per
entry (safe to replay on every deploy), and `Drizzle.migrationSql(names?)`
joins them into a single script. Verbatim, under the default names:

```sql
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

The test suite runs against
[PGlite](https://github.com/electric-sql/pglite) (PostgreSQL compiled to
WebAssembly, in-process, no server), so `jsonb`, `timestamptz`, `RETURNING` and
unique-index violations behave exactly as they do in production. One file per
store, plus `Requests.test.ts`, which counts the SQL a program emits through
drizzle's own `logger` hook to prove the batching claims above.

```sh
pnpm run test
```

## License

MIT
