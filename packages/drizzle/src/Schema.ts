/**
 * What the three auth tables are called, and the dialect-independent shape the
 * stores address them through.
 *
 * The tables themselves are defined once per dialect — `Pg`, `Sqlite` and
 * `MySql` — because a drizzle table object is branded by its dialect. This
 * module holds what those three definitions agree on: the table names, the
 * {@link Tables} set a store factory takes, and the row types it reads back.
 *
 * ### Column conventions, in the abstract
 *
 * Every dialect maps the same six semantics; only the physical types differ.
 *
 * | Semantic          | PostgreSQL              | SQLite                     | MySQL             |
 * | ----------------- | ----------------------- | -------------------------- | ----------------- |
 * | id / handle text  | `text`                  | `text`                     | `varchar(255)`    |
 * | instant           | `timestamptz` (`Date`)  | `integer` epoch ms (`Date`)| `datetime(3)`     |
 * | attribute bag     | `jsonb`                 | `text` (JSON mode)         | `json`            |
 * | boolean           | `boolean`               | `integer` 0/1              | `tinyint` 0/1     |
 *
 * All four round-trip to the *same* TypeScript values — `string`, `Date`,
 * `Record<string, unknown>`, `boolean` — which is why one store implementation
 * serves all three. Column names are identical across dialects.
 *
 * ### Tables this package did not define
 *
 * Everything here describes the tables this package builds. An application
 * adopting effect-auth onto tables it already owns — its own column names, its
 * own key types — maps them instead; see `Columns.ts` and `defineSchema`.
 *
 * ### What is *not* here
 *
 * `effect_auth_users` carries no `email`/`email_verified` columns. Since the
 * surrogate-key migration, login handles live exclusively in
 * `effect_auth_identifiers` — a user may hold several emails, a username and a
 * phone number, or none at all.
 */

import type * as MySql from "./MySqlSchema.ts";
import type * as Pg from "./PgSchema.ts";
import type * as Sqlite from "./SqliteSchema.ts";

// ---------------------------------------------------------------------------
// Table names
// ---------------------------------------------------------------------------

/** The physical table name for each of the three auth tables. */
export interface TableNames {
  readonly sessions: string;
  readonly users: string;
  readonly identifiers: string;
}

/** The default `effect_auth_*` table names, shared by every dialect. */
export const defaultTableNames: TableNames = {
  sessions: "effect_auth_sessions",
  users: "effect_auth_users",
  identifiers: "effect_auth_identifiers",
};

// ---------------------------------------------------------------------------
// Tables
// ---------------------------------------------------------------------------

/**
 * The set of tables a store factory reads and writes: one dialect's three
 * tables, never a mixture.
 *
 * The union is what makes the stores dialect-generic without giving up type
 * safety — `Pg.defineTables()`, `Sqlite.defineTables()` and
 * `MySql.defineTables()` each produce one member, and every member yields the
 * same row and insert shapes, so the store code is written once.
 */
export type Tables = Pg.Tables | Sqlite.Tables | MySql.Tables;

/** Row shapes selected from each table, whichever dialect produced them. */
export type SessionRow = Tables["sessions"]["$inferSelect"];
export type UserRow = Tables["users"]["$inferSelect"];
export type IdentifierRow = Tables["identifiers"]["$inferSelect"];
