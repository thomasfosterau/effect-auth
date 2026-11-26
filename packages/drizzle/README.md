# @thomasfosterau/effect-auth-drizzle

Storage layers for [`@thomasfosterau/effect-auth`](https://github.com/thomasfosterau/effect-auth/tree/trunk/packages/effect-auth), built on
[Drizzle ORM](https://orm.drizzle.team) — **PostgreSQL, SQLite and MySQL**.

Implements the three stores every sign-in flow touches, and the five that
sign-up, password reset, email verification, user management (`UserService`,
account management, admin), API keys and rate limiting need:

| effect-auth tag                                      | Table                     | What it holds                                          |
| ---------------------------------------------------- | ------------------------- | ------------------------------------------------------ |
| `SessionStore`                                       | `effect_auth_sessions`    | Sessions keyed by the SHA-256 hash of the bearer token |
| `UserStore`                                          | `effect_auth_users`       | User records                                           |
| `IdentifierStore`                                    | `effect_auth_identifiers` | Email / username / phone claims, unique per pair       |
| `Email.EmailPasswordStore`, `PasswordResetUserStore` | `effect_auth_users`       | New users, and their `password_hash`                   |
| `UserServiceStore`                                   | `effect_auth_users`       | User reads, profile / attribute updates and deletes    |
| `ApiKeyStore`                                        | `effect_auth_api_keys`    | API keys by the SHA-256 hash of the key                |
| `RateLimitStore`                                     | `effect_auth_rate_limits` | One fixed-window counter per rate-limit key            |
| `EmailVerificationStore`, `PasswordResetStore`       | `effect_auth_tokens`      | Pending verification and reset tokens, by hash         |

This package **stands alone** — it does not wrap
[`@thomasfosterau/effect-auth/sql`](https://github.com/thomasfosterau/effect-auth/tree/trunk/packages/effect-auth/src/sql). It speaks drizzle's query builder
directly, so attribute bags and timestamps are round-tripped natively by the
driver instead of being encoded into `TEXT`. If you want a driver-agnostic layer
covering _every_ effect-auth store (OAuth, WebAuthn, rate limits, ...), reach
for the core's `/sql` subpath instead; use this one when your app already models its
schema in drizzle and you want the auth tables to live in the same migration
pipeline.

## Install

```sh
pnpm add @thomasfosterau/effect-auth-drizzle @thomasfosterau/effect-auth drizzle-orm effect
```

`drizzle-orm` (`>=1.0.0-rc.5 <2`) and `effect` (`^4.1.0`) are peer dependencies, as is your driver of choice (`pg`,
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

const db = drizzle({ client: new Pool({ connectionString: process.env.DATABASE_URL }) });

const stores = Drizzle.layer().pipe(Layer.provide(Drizzle.databaseLayer(db)));
```

## Entry points

| Export                                                                         | What it is                                                                            |
| ------------------------------------------------------------------------------ | ------------------------------------------------------------------------------------- |
| `layer(schema?)`                                                               | All three stores at once, over a dialect's `tables` or an `AuthSchema`                |
| `databaseLayer(db)`, `effectDatabaseLayer(db)`                                 | The database seam for Promise and Effect drivers (`DrizzleDatabase`)                  |
| `SessionStore`, `UserStore`, `IdentifierStore`                                 | One namespace per store: `make`, `layer`, requests, resolvers                         |
| `SingleTableIdentifierStore`                                                   | The opt-in one-email-per-user store over your own `users` table                       |
| `Requests`                                                                     | The batched read interface                                                            |
| `Pg`, `Sqlite`, `MySql`                                                        | One namespace per dialect: tables, `defineTables`, DDL (`MySql` also `binaryVarchar`) |
| `defineSchema`, `fromTables`, `AuthSchema` and column types                    | The stores pointed at tables you already have                                         |
| `defineApiKeyTable`, `defineTokenTable`, `defineRateLimitTable`                | `ApiKeyStore`, `TokenStore`, `RateLimitStore` pointed at tables you already have      |
| `TableNames`, `defaultTableNames`, `Tables`, row types                         | What the three dialects agree on                                                      |
| `ladderCheck(column, ladder)`                                                  | A role column's `CHECK` derived from an `Auth.Ladder`                                 |
| `ownedListFilter(columns)`, `isFollowerLayer`, `isMemberLayer`, `OwnedColumns` | `Auth.OwnedAccess` read scopes rendered as a drizzle `WHERE`                          |

## Guide

The [Drizzle storage guide](https://github.com/thomasfosterau/effect-auth/blob/trunk/docs/guides/drizzle.md) covers the supported drizzle-orm versions, the per-store layers, dialects (MySQL included), batched reads, Effect drivers and transactions, the schema and migrations, adopting an existing schema with `defineSchema`, the authorization helpers, single-table identifiers, the stores beyond sign-in and their semantics.

## License

MIT
