/**
 * Helpers for inspecting and tearing down the effect-auth schema in a
 * Cloudflare D1 database.
 *
 * The canonical table list is derived from the `schemaStatements` defined in
 * `./Schema.ts`, so it stays in lock-step with the schema this package actually
 * creates — there is no second copy to drift.
 */

import { Effect } from "effect";
import type * as Auth from "effect-auth";
import { d1All, d1Run, type D1Database } from "./D1.js";
import { schemaStatements } from "./Schema.js";

const CREATE_TABLE = /create\s+table\s+if\s+not\s+exists\s+(\w+)/i;

/**
 * Every table the effect-auth schema creates, in declaration order. Parsed once
 * from `schemaStatements` (e.g. `auth_users`, `auth_sessions`, ...).
 */
export const authTableNames: readonly string[] = schemaStatements.flatMap((sql) => {
  const match = CREATE_TABLE.exec(sql);
  return match ? [match[1] as string] : [];
});

/** Row shape returned when querying `sqlite_master` for table names. */
interface TableNameRow {
  readonly name: string;
}

/**
 * List the auth tables that currently exist in the database, sorted by name.
 *
 * Matches the `auth_` prefix (with `_` escaped so it is a literal underscore,
 * not a SQL `LIKE` wildcard) so the application's own tables are never
 * included.
 */
export const listAuthTables = (db: D1Database): Effect.Effect<readonly string[], Auth.AuthError> =>
  d1All<TableNameRow>(
    db,
    "SELECT name FROM sqlite_master WHERE type = 'table' AND name LIKE 'auth\\_%' ESCAPE '\\' ORDER BY name",
    [],
    "list-auth-tables",
  ).pipe(Effect.map((rows) => rows.map((row) => row.name)));

/**
 * Drop every effect-auth table. Idempotent (`DROP TABLE IF EXISTS`), so it is
 * safe to call when some or all tables are already gone.
 */
export const dropAuthTables = (db: D1Database): Effect.Effect<void, Auth.AuthError> =>
  Effect.forEach(
    authTableNames,
    (name) => d1Run(db, `DROP TABLE IF EXISTS ${name}`, [], "drop-auth-table"),
    {
      discard: true,
    },
  );
