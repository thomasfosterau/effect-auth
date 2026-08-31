/**
 * The service seam between effect-auth's stores and a Drizzle database handle —
 * PostgreSQL, SQLite or MySQL.
 *
 * This package never opens a connection of its own: the application builds a
 * drizzle handle with whichever driver it already uses (`node-postgres`,
 * `postgres.js`, Neon, PGlite, `better-sqlite3`, libSQL, D1, `mysql2`, ...) and
 * hands it over as the {@link DrizzleDatabase} service.
 *
 * ### Why a structural seam
 *
 * The store code is single-sourced across all three dialects because the
 * fragment of drizzle's query builder it uses — `insert().values()`,
 * `select().from().where().limit()/.orderBy()`, `update().set().where()`,
 * `delete().where()`, all terminated by `.execute()` — is spelled identically by
 * `PgDatabase`, `BaseSQLiteDatabase` and `MySqlDatabase`. What is *not* shared
 * is their static types: each dialect brands its own `PgTable` / `SQLiteTable` /
 * `MySqlTable`, so no single drizzle type covers the three.
 *
 * {@link AuthDatabase} is therefore a minimal structural description of exactly
 * that fragment, and nothing else — it carries no `any`, and every row and
 * insert type is still derived from the table it was given. {@link databaseLayer}
 * is the one door a real handle comes through, and its overloads accept only
 * genuine `PgDatabase` / `BaseSQLiteDatabase` / `MySqlDatabase` values (schema
 * generics inferred, transaction handles included).
 *
 * @example
 * ```ts
 * import { Layer } from "effect";
 * import { drizzle } from "drizzle-orm/node-postgres";
 * import { Pool } from "pg";
 * import * as Drizzle from "@thomasfosterau/effect-auth-drizzle";
 *
 * const db = drizzle(new Pool({ connectionString: process.env["DATABASE_URL"] }));
 * const stores = Drizzle.layer().pipe(Layer.provide(Drizzle.databaseLayer(db)));
 * ```
 */

import { Context, Layer } from "effect";
import type { SQL, SQLWrapper, Table, TablesRelationalConfig } from "drizzle-orm";
import type {
  MySqlDatabase,
  MySqlQueryResultHKT,
  PreparedQueryHKTBase,
} from "drizzle-orm/mysql-core";
import type { PgDatabase, PgQueryResultHKT } from "drizzle-orm/pg-core";
import type { BaseSQLiteDatabase } from "drizzle-orm/sqlite-core";

// ---------------------------------------------------------------------------
// The query-builder fragment the stores use
// ---------------------------------------------------------------------------

/** A drizzle query that has been fully built and can be run. */
export interface DrizzleExecutable<out A> {
  execute(): Promise<A>;
}

/** The rows a `SELECT *` over `TTable` yields. */
export type DrizzleRows<TTable extends Table> = Array<TTable["$inferSelect"]>;

/**
 * A `SELECT` with its `WHERE` already applied: it can still be narrowed by
 * `limit`/`orderBy`, or run as-is.
 */
export interface DrizzleSelectFiltered<TTable extends Table> extends DrizzleExecutable<
  DrizzleRows<TTable>
> {
  limit(limit: number): DrizzleExecutable<DrizzleRows<TTable>>;
  orderBy(...columns: Array<SQLWrapper>): DrizzleExecutable<DrizzleRows<TTable>>;
}

/** A `SELECT ... FROM table`, before any `WHERE`. */
export interface DrizzleSelectFrom<TTable extends Table> extends DrizzleSelectFiltered<TTable> {
  where(where: SQL | undefined): DrizzleSelectFiltered<TTable>;
}

/** The value `db.select()` returns. */
export interface DrizzleSelectBuilder {
  from<TTable extends Table>(table: TTable): DrizzleSelectFrom<TTable>;
}

/** The value `db.insert(table)` returns. */
export interface DrizzleInsertBuilder<TTable extends Table> {
  values(values: TTable["$inferInsert"]): DrizzleExecutable<unknown>;
}

/** A statement whose only remaining step is its `WHERE`. */
export interface DrizzleWhereStep {
  where(where: SQL | undefined): DrizzleExecutable<unknown>;
}

/** The value `db.update(table)` returns. */
export interface DrizzleUpdateBuilder<TTable extends Table> {
  set(values: Partial<TTable["$inferInsert"]>): DrizzleWhereStep;
}

/**
 * Every drizzle database operation this package performs, in the smallest shape
 * that describes them.
 *
 * A `PgDatabase`, a `BaseSQLiteDatabase` (sync or async) and a `MySqlDatabase`
 * all implement this fragment at runtime; {@link databaseLayer} is what turns a
 * concrete handle into one.
 */
export interface AuthDatabase {
  select(): DrizzleSelectBuilder;
  insert<TTable extends Table>(table: TTable): DrizzleInsertBuilder<TTable>;
  update<TTable extends Table>(table: TTable): DrizzleUpdateBuilder<TTable>;
  delete<TTable extends Table>(table: TTable): DrizzleWhereStep;
}

// ---------------------------------------------------------------------------
// Service
// ---------------------------------------------------------------------------

/**
 * Tag for the drizzle database handle the stores read out of context.
 *
 * Provide it with {@link databaseLayer}, which accepts a handle from any of the
 * three supported dialects.
 */
export class DrizzleDatabase extends Context.Service<DrizzleDatabase, AuthDatabase>()(
  "@effect-auth/DrizzleDatabase",
) {}

/**
 * Provide an already-constructed drizzle handle as {@link DrizzleDatabase}.
 *
 * Accepts any PostgreSQL, SQLite or MySQL handle — `drizzle(...)` from any
 * driver, and the transaction handle passed to `db.transaction(...)`, since
 * each dialect's transaction type extends its database type.
 *
 * Pair it with the tables for the *same* dialect (`Pg.tables`, `Sqlite.tables`
 * or `MySql.tables`); the store layers take those separately, so the pairing is
 * the caller's to get right.
 */
export function databaseLayer<
  TQueryResult extends PgQueryResultHKT,
  TFullSchema extends Record<string, unknown>,
  TSchema extends TablesRelationalConfig,
>(db: PgDatabase<TQueryResult, TFullSchema, TSchema>): Layer.Layer<DrizzleDatabase>;
export function databaseLayer<
  TResultKind extends "sync" | "async",
  TRunResult,
  TFullSchema extends Record<string, unknown>,
  TSchema extends TablesRelationalConfig,
>(
  db: BaseSQLiteDatabase<TResultKind, TRunResult, TFullSchema, TSchema>,
): Layer.Layer<DrizzleDatabase>;
export function databaseLayer<
  TQueryResult extends MySqlQueryResultHKT,
  TPreparedQueryHKT extends PreparedQueryHKTBase,
  TFullSchema extends Record<string, unknown>,
  TSchema extends TablesRelationalConfig,
>(
  db: MySqlDatabase<TQueryResult, TPreparedQueryHKT, TFullSchema, TSchema>,
): Layer.Layer<DrizzleDatabase>;
export function databaseLayer(db: object): Layer.Layer<DrizzleDatabase> {
  // The one erasure in the package. Each dialect's `select().from()` is
  // *constrained* to its own table brand (`PgTable`, `SQLiteTable`,
  // `MySqlTable`), so no dialect handle is assignable to a signature generic
  // over drizzle's shared `Table` — even though all three implement it at
  // runtime, which is precisely what the overloads above have just checked.
  return Layer.succeed(DrizzleDatabase, db as AuthDatabase);
}
