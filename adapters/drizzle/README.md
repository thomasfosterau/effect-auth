# @effect-auth/adapter-drizzle

Drizzle ORM adapter for [effect-auth](https://github.com/thomasfosterau/effect-auth).

Implements the `SessionStore` and `UserStore` interfaces from `effect-auth` using a
PostgreSQL database via Drizzle ORM.

## Installation

```sh
npm install @effect-auth/adapter-drizzle drizzle-orm effect effect-auth
```

## Quick Start

```ts
import { drizzle } from "drizzle-orm/node-postgres"
import { Pool } from "pg"
import { Layer } from "effect"
import { makeSessionManager } from "effect-auth"
import {
  DrizzleDatabase,
  DrizzleSessionStoreLive,
  DrizzleUserStoreLive,
} from "@effect-auth/adapter-drizzle"

const pool = new Pool({ connectionString: process.env.DATABASE_URL })

const DatabaseLive = Layer.succeed(DrizzleDatabase, drizzle(pool))

const StoreLive = Layer.mergeAll(
  DrizzleSessionStoreLive,
  DrizzleUserStoreLive,
).pipe(Layer.provide(DatabaseLive))
```

## Schema

The adapter ships with ready-to-use PostgreSQL table definitions. Run the
following migration to create the required tables:

```sql
CREATE TABLE effect_auth_sessions (
  id               TEXT        PRIMARY KEY,
  user_id          TEXT        NOT NULL,
  expires_at       TIMESTAMPTZ NOT NULL,
  created_at       TIMESTAMPTZ NOT NULL,
  last_activity_at TIMESTAMPTZ NOT NULL,
  attributes       JSONB       NOT NULL DEFAULT '{}'
);

CREATE TABLE effect_auth_users (
  id              TEXT  PRIMARY KEY,
  attributes      JSONB NOT NULL DEFAULT '{}',
  hashed_password TEXT
);
```

Or import and use the Drizzle schema objects directly with your preferred
migration tool:

```ts
import { sessionsTable, usersTable } from "@effect-auth/adapter-drizzle"
```

## Custom Tables

If you already have existing tables, pass them to the factory functions:

```ts
import { makeDrizzleSessionStoreLive, makeDrizzleUserStoreLive } from "@effect-auth/adapter-drizzle"
import { mySessionsTable, myUsersTable } from "./schema.js"

const SessionStoreLive = makeDrizzleSessionStoreLive(mySessionsTable)
const UserStoreLive    = makeDrizzleUserStoreLive(myUsersTable)
```

Your custom tables must expose the same **Drizzle column keys** (TypeScript
property names) as the default schema:

| TypeScript key     | Default DB column name |
|--------------------|------------------------|
| `id`               | `id`                   |
| `userId`           | `user_id`              |
| `expiresAt`        | `expires_at`           |
| `createdAt`        | `created_at`           |
| `lastActivityAt`   | `last_activity_at`     |
| `attributes`       | `attributes`           |
| `hashedPassword`   | `hashed_password`      |

Drizzle maps between camelCase TypeScript keys and snake\_case SQL column names
automatically when you use the two-argument form in your schema definition,
e.g. `text("user_id")`.

## License

ISC
