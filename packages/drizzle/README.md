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
pnpm add @thomasfosterau/effect-auth-drizzle drizzle-orm effect
```

`drizzle-orm` and `effect` are peer dependencies, as is your driver of choice (`pg`,
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
that, the same four read paths are also exposed as Effect `Request`s backed by
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

| Constructor                                  | Request                 | Resolves to                 |
| -------------------------------------------- | ----------------------- | --------------------------- |
| `Requests.getSession(id)`                    | `GetSession`            | `Session \| null`           |
| `Requests.getUser(id)`                       | `GetUser`               | `User \| null`              |
| `Requests.getIdentifierByValue(type, value)` | `GetIdentifierByValue`  | `Identifier \| null`        |
| `Requests.listIdentifiersByUser(userId)`     | `ListIdentifiersByUser` | `ReadonlyArray<Identifier>` |

Each returns an `Effect<…, AuthError, AuthRequests>`; provide
`Drizzle.Requests.layer()` (on top of a `DrizzleDatabase` layer) to satisfy it.

What the resolvers do inside a batch:

- **De-duplicate.** Twenty concurrent `getUser("u1")` are one row read, not
  twenty.
- **Coalesce.** Different ids in the same batch become one
  `WHERE id IN (...)`.
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

## Effect drivers, request-scoped pools and transactions

Drizzle's Effect drivers (`drizzle-orm/effect-postgres` and its siblings, drizzle
`1.0`) build queries that _are_ `Effect`s. Bind one with `effectDatabaseLayer`
and the stores run its queries directly — there is no Promise boundary anywhere
between `Auth.SessionStore` and the database.

**On Cloudflare Workers, a pool's sockets are pinned to the request that opened
them**: a pool shared across requests deadlocks every later request, so each
request has to bring its own. Both `databaseLayer` and `effectDatabaseLayer`
therefore accept an `Effect` that yields the handle, not only a handle. The
`Effect` is run once per query, in the calling fiber, so a handle the
application keeps in a `Context.Reference` (or any per-request service) follows
the request that set it — the request scope _is_ the Effect context, and no
`AsyncLocalStorage` is needed. Passing a plain handle pins it for the life of
the layer, which is right for a long-lived server and wrong on Workers.

**Transactions compose the same way.** Inside an application's own
`db.transaction((tx) => …)` on an Effect driver, every store call — the direct
methods and the batched `Requests` alike — runs on the transaction's fiber, so
`@effect/sql` picks the transaction's connection for it: the stores see the
transaction's uncommitted writes and commit or roll back with it.
`Transaction.test.ts` pins this per query. (A Promise-bridged adapter has to
capture and re-provide the transaction fiber's services by hand to get the same
property; these stores need nothing of the kind because they never leave the
caller's fiber.)

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
claim mechanism behind `Auth.claimIdentifier`. For an application whose users
table holds the email itself, see
[Single-table identifiers](#single-table-identifiers-opt-in).

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

## Single-table identifiers (opt-in)

The default `IdentifierStore` keeps identifiers in `effect_auth_identifiers`, so
a user may hold several emails, a username and a phone number. An application
whose `users` table already carries the login address, as `email` and
`email_verified` columns on the row, can use `SingleTableIdentifierStore`
instead. It reads and writes that row directly, so there is no identifiers table
to migrate onto.

The trade-off is that a user has **one identifier, and it is an email**. The
store does not hold a second address, a username or a phone number, and refuses
them with an `AuthError` rather than dropping the write.

```ts
import { Layer } from "effect";
import * as Drizzle from "@thomasfosterau/effect-auth-drizzle";

// The application's own table: a unique email, nullable or NOT NULL.
const users = Drizzle.SingleTableIdentifierStore.defineUsers({
  table: appUsers,
  columns: {
    id: "userId",
    email: "email",
    emailVerified: "emailVerified",
    emailVerifiedAt: "emailVerifiedAt", // optional; see below
    createdAt: "createdAt",
  },
});

const identifiers = Drizzle.SingleTableIdentifierStore.layer(users).pipe(
  Layer.provide(Drizzle.databaseLayer(db)),
);
```

Column names are the table object's keys, as in `defineSchema`. The store is not
part of `Drizzle.layer()`, so choosing it is an explicit provide.

### What the table has to satisfy

- **`email` has a unique index.** The index is the only thing that stops two
  users holding one address; the store does not check it. Without it, two users
  can own one address and `getByValue`'s `LIMIT 1` picks one. Create it per
  dialect:

  ```sql
  -- PostgreSQL
  CREATE UNIQUE INDEX app_users_email_key ON app_users (email);

  -- SQLite
  CREATE UNIQUE INDEX app_users_email_key ON app_users (email);

  -- MySQL: the column must be VARCHAR(n), not TEXT, to be indexed
  CREATE UNIQUE INDEX app_users_email_key ON app_users (email);
  ```

  A unique index admits several `NULL`s on all three dialects, so a nullable
  `email` is fine with it.

- **`email` is nullable or `NOT NULL`.** The store detects which from the column
  when you call `defineUsers`. See [Nullable or NOT NULL](#nullable-or-not-null-email).
- **`email_verified` is a non-null boolean.**
- **`email_verified_at`, if you map it, is a nullable timestamp.**
- **Your user writer inserts the row.** The store never inserts a user. Core
  passes the address a user signs up with to your `createUser` as
  `input.identifier`; write it into the row on insert (see
  [Sign-up](#sign-up-the-address-at-creation)), or, on a nullable column, leave
  it out and the claim that follows writes it. Report `created: true` only for
  a row this call inserted.

Nothing else on the row is written, including `updated_at`.

### Nullable or NOT NULL email

The store reads the column's `NOT NULL` setting, so both shapes work without any
option:

- **Nullable** (the usual case). Deleting an address writes `NULL` to `email`
  and `false` to `email_verified`, and the row stays. Account deletion clears the
  address and then deletes the row. An address can be claimed again once it is
  cleared.
- **`NOT NULL`.** The store never writes `NULL`, so an address cannot be removed
  from the row while the row exists:
  - Deleting a user's address by identifier is refused with an `AuthError`,
    and the address stays.
  - `deleteByUser` does nothing. Account deletion deletes the user row right
    after it, and the address goes with the row, so account deletion works. An
    application that calls `deleteByUser` and keeps the row keeps the address.
    This departs from the `IdentifierStore` contract, which says `deleteByUser`
    deletes all of a user's identifiers. It relies on your user writer
    hard-deleting the row. A soft-delete writer, one that keeps the row and marks
    it deleted, leaves the address claimed, so no one else can register it.
  - Sign-up works when your user writer inserts the row with the address core
    passes it (see [Sign-up](#sign-up-the-address-at-creation)). A writer that
    leaves the address out cannot insert the row: the database refuses it, and
    sign-up fails with an `AuthError`.
  - Email change works: core's confirmation goes through `replace`, which
    rewrites the address in one `UPDATE` and never writes `NULL`.
  - A user whose row holds an address cannot be given a second one, which is
    the same refusal as on a nullable column.

  Every user row holds an address, so a flow that creates a user without one
  (anonymous sign-in, phone OTP sign-up) cannot run on a `NOT NULL` column.

### Sign-up: the address at creation

Core flows that create a user for a known address (email and password sign-up,
magic link, email OTP, OAuth, SSO and Google One Tap first sign-in, SCIM and
admin creation) pass it to the store's `createUser` as `input.identifier`: its
`type`, normalised `value`, `verified` flag and, when verified, `verifiedAt`.
Your writer puts it on the row it inserts, and the claim that follows finds the
address already there and writes nothing more.

`createUser` resolves to `{ user, created }`. `created` is `true` only when this
call inserted the user. Core treats an address already on the row as the new
user's own only when `created` is `true`. A writer that finds or creates on the
address, and returns a user who already existed, must report `created: false`;
sign-up then fails as the address being in use (`EmailInUseError` for email and
password sign-up) and writes nothing to that user, so it cannot set a password
on, link an account to, or verify someone else's account.

When the user already exists, the writer must not modify that row. Core sees
`created` only after the write, so `onConflictDoUpdate` has already copied the
caller's fields onto someone else's account. Use a plain `INSERT`, as below,
and let the unique index on `email` fail (core maps that failure to the address
being in use), or `onConflictDoNothing()` followed by a select of the existing
row, reported as `created: false`. Never `onConflictDoUpdate`. A plain `INSERT`
always reports `true`.

On a `NOT NULL` `email` column the row can't be inserted without the address,
so the writer fails when there is none:

```ts
import { Effect } from "effect";
import * as Auth from "@thomasfosterau/effect-auth";

// `email` NOT NULL: the row can't be inserted without the address.
const createUser: (typeof Auth.Email.EmailPasswordStore.Service)["createUser"] = (input) =>
  Effect.gen(function* () {
    const email = input.identifier;
    if (email?.type !== "email") {
      return yield* new Auth.AuthError({ message: "A user needs an email address" });
    }
    const id = crypto.randomUUID();
    const now = new Date();
    yield* Effect.tryPromise({
      try: () =>
        db.insert(appUsers).values({
          userId: id,
          name: input.name ?? null,
          email: email.value,
          emailVerified: email.verified,
          emailVerifiedAt: email.verifiedAt ?? null, // only if the table maps it
          createdAt: now,
          updatedAt: now,
        }),
      catch: (cause) => new Auth.AuthError({ message: "insert into users failed", cause }),
    });
    // A plain INSERT: when it succeeds, this call created the user.
    const user = {
      id,
      ...(input.name !== undefined && { name: input.name }),
      createdAt: now,
      updatedAt: now,
      attributes: {},
    };
    return { user, created: true };
  });
```

On a nullable column the writer can insert the row without an address, and the
claim that follows writes it:

```ts
import { Effect } from "effect";
import * as Auth from "@thomasfosterau/effect-auth";

// `email` nullable: a user created without an address gets `NULL`.
const createUser: (typeof Auth.Email.EmailPasswordStore.Service)["createUser"] = (input) =>
  Effect.gen(function* () {
    const email = input.identifier?.type === "email" ? input.identifier : undefined;
    const id = crypto.randomUUID();
    const now = new Date();
    yield* Effect.tryPromise({
      try: () =>
        db.insert(appUsers).values({
          userId: id,
          name: input.name ?? null,
          email: email?.value ?? null,
          emailVerified: email?.verified ?? false,
          emailVerifiedAt: email?.verifiedAt ?? null, // only if the table maps it
          createdAt: now,
          updatedAt: now,
        }),
      catch: (cause) => new Auth.AuthError({ message: "insert into users failed", cause }),
    });
    // A plain INSERT: when it succeeds, this call created the user.
    const user = {
      id,
      ...(input.name !== undefined && { name: input.name }),
      createdAt: now,
      updatedAt: now,
      attributes: {},
    };
    return { user, created: true };
  });
```

Drop `emailVerifiedAt` from the insert if your table doesn't map it. The users
table's unique index decides a race between two sign-ups for one address: the
losing insert fails, and core reports it as the address being in use, as it
does when the claim loses on a store with an identifiers table. If the writer
stores the address but not its `verified` flag, the claim marks the row verified
when the flow asked for a verified address.

### `verifiedAt`: mapped or not

`verifiedAt` is stored only when you map `emailVerifiedAt`. When it is mapped:

- `setVerified(id, verifiedAt)` stores the timestamp in that column, and reads
  report it as the identifier's `verifiedAt`.
- A claim that carries a `verifiedAt` stores it too.
- Deleting the address clears the column.

When it is not mapped, `verifiedAt` isn't stored: the argument is dropped, and no
read reports one. The `verified` flag is always stored, in `email_verified`.

### How each field maps

| `Identifier` field | Stored in                                                                 |
| ------------------ | ------------------------------------------------------------------------- |
| `id`, `userId`     | the user's id; an email identifier's id is its user's id                  |
| `type`             | always `"email"`                                                          |
| `value`            | `email`                                                                   |
| `verified`         | `email_verified`                                                          |
| `verifiedAt`       | `email_verified_at`, when mapped; otherwise not stored, so never reported |
| `createdAt`        | the user row's creation time                                              |

A user whose `email` is `NULL` holds no identifier.

### Method behaviour

- `getByValue` looks up `email`. Any other type returns `null`.
- `create` refuses a type other than `email`, a user with no row, and a user
  that already holds an address. A duplicate address owned by another user
  fails through the unique index as `AuthError`, which `claimIdentifier` reports
  as `IdentifierTakenError`, as it does for the default store.
- `replace` rewrites the row's address in one statement,
  `UPDATE … SET email = <new>, email_verified = <new flag>[, email_verified_at = <new time>] WHERE id = <user> AND email = <old>`,
  then reads the row back. The guard on the old address means a stale call
  writes nothing and resolves to `null`. An address another user holds fails
  through the unique index as `AuthError`, which `replaceIdentifier` reports as
  `IdentifierTakenError`, and the row keeps its address. The identifier keeps
  the user's id and the row's creation time. It works on nullable and `NOT NULL`
  columns alike.
- `delete` and `deleteByUser` follow the column's nullability, described above.

### Email change

Core's `AccountManagement.confirmEmailChange` changes the address through
`IdentifierStore.replace`, so it works on this store, on nullable and `NOT NULL`
columns. The row holds the new address, verified, and the confirm token is
consumed. If another user takes the new address first, the confirmation fails
with `AccountTokenError` ("Email already in use") and the row keeps the previous
address.

### Flows this store does not support

- **Batched reads.** `Requests.getIdentifierByValue` and
  `Requests.listIdentifiersByUser` read the default identifiers table, so they
  don't apply to this store. `Requests.getUser` and `Requests.getSession` are
  unaffected.
- **SCIM `userName` change.** It adds the new address before it removes the old
  one, so the store refuses it with an `AuthError`. The SCIM route answers that
  with a `500` today, not a client error.
- **Admin `identifiers[]` extras, and the username and phone-number flows.** This
  store holds only email identifiers, so these are refused with an `AuthError`.

## Store semantics

The stores implement effect-auth's contracts exactly:

- **`null` on a miss.** `get`, `getByValue` and `setVerified` return `null`
  rather than failing when there is no matching row, and `replace` returns
  `null` when the identifier it replaces is no longer the user's.
- **Deletes are no-ops** when the row does not exist.
- **Driver failures become `AuthError`** with the original error preserved as
  `cause` — including the unique-index violation raised when two users race for
  the same `(type, value)`. `Auth.claimIdentifier` and `Auth.replaceIdentifier`
  in core re-read the pair on failure and turn that race into an
  `IdentifierTakenError`.
- **`IdentifierStore.replace` claims, then releases.** The default store inserts
  the new identifier and then deletes the old one. It opens no transaction of its
  own: on a handle inside your transaction the two commit or roll back together;
  otherwise each autocommits, and a failure between them leaves the user holding
  both, never neither. Confirming an email change again releases the old one.
  A value another user holds is refused before anything is deleted.
- **Password hashes live outside `UserStore`.** Reading and writing
  `password_hash` is the job of a store this package does not implement yet
  (`EmailPasswordStore`), so pair it with the `sql` package or your own writer
  for sign-up flows.
- **Session ids are token hashes.** The service layer hashes the bearer token
  before it reaches the store; the database never sees a raw token.

Stores beyond these three — OAuth accounts, WebAuthn credentials, rate limits,
and the rest — are not covered here yet.

## License

MIT
