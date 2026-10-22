/**
 * The service seam between effect-auth's stores and a Drizzle database handle —
 * PostgreSQL, SQLite or MySQL, Promise-shaped or Effect-shaped.
 *
 * This package never opens a connection of its own: the application builds a
 * drizzle handle with whichever driver it already uses (`node-postgres`,
 * `postgres.js`, Neon, PGlite, `better-sqlite3`, libSQL, D1, `mysql2`,
 * `effect-postgres`, ...) and hands it over as the {@link DrizzleDatabase}
 * service.
 *
 * ### Why a structural seam
 *
 * The store code is single-sourced across all dialects because the fragment of
 * drizzle's query builder it uses — `insert().values()`,
 * `select().from().where().limit()/.orderBy()`, `update().set().where()`,
 * `delete().where()`, all terminated by `.execute()` — is spelled identically by
 * `PgDatabase`, `BaseSQLiteDatabase`, `MySqlDatabase` and drizzle's Effect
 * drivers. What is *not* shared is their static types: each dialect brands its
 * own `PgTable` / `SQLiteTable` / `MySqlTable`, so no single drizzle type covers
 * them.
 *
 * {@link AuthDatabase} is therefore a minimal structural description of exactly
 * that fragment, and nothing else — it carries no `any`, and every row and
 * insert type is still derived from the table it was given. {@link databaseLayer}
 * and {@link effectDatabaseLayer} are the doors a real handle comes through.
 *
 * ### Promise-shaped and Effect-shaped drivers
 *
 * `.execute()` returns a `Promise` on the classic drivers and an `Effect` on
 * drizzle's Effect drivers (`drizzle-orm/effect-postgres` and friends, new in
 * drizzle `1.0`). {@link DrizzleResult} is the union of the two, and the store
 * layer adapts at runtime — an Effect-shaped handle reaches the database with
 * no Promise round trip in between.
 *
 * ### Handle lifetime
 *
 * {@link DrizzleDatabase} does not hold a handle; it holds an
 * `Effect<AuthDatabase>` that is run *once per query*. Passing a plain handle
 * pins it for the life of the layer, exactly as before. Passing an `Effect`
 * defers the choice to the calling fiber, which is what a request-scoped pool
 * needs: on Cloudflare Workers a pool's sockets are pinned to the request that
 * opened them, so an isolate serving overlapping requests must resolve the
 * handle per query rather than capture one at layer-build time. A
 * `Context.Reference` holding the handle does that with no `AsyncLocalStorage`:
 * the request scope *is* the Effect context.
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
 *
 * @example
 * ```ts
 * // A handle resolved per query, from the calling request's scope.
 * import { Context, Effect, Layer } from "effect";
 * import * as Drizzle from "@thomasfosterau/effect-auth-drizzle";
 *
 * const RequestDatabase = Context.Reference<PgDatabase<PgQueryResultHKT>>(
 *   "app/RequestDatabase",
 *   { defaultValue: () => fallbackHandle },
 * );
 *
 * // Built once, for the whole isolate — it holds no connection.
 * const stores = Drizzle.layer().pipe(Layer.provide(Drizzle.databaseLayer(RequestDatabase)));
 *
 * // Per request, in that request's scope:
 * const handler = program.pipe(Effect.provide(Context.make(RequestDatabase, thisRequestsDb)));
 * ```
 */

import { Context, Effect, Layer } from "effect";
import type {
  Column,
  InferColumnsDataTypes,
  SQL,
  SQLWrapper,
  Table,
  TablesRelationalConfig,
} from "drizzle-orm";
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

/**
 * What running a built drizzle query yields.
 *
 * The classic drivers resolve a `Promise`; drizzle's Effect drivers return an
 * `Effect` whose error channel carries the driver's own query error. The store
 * layer accepts either, so a driver change never reaches the store code.
 */
export type DrizzleResult<A> = Promise<A> | Effect.Effect<A, unknown>;

/** A drizzle query that has been fully built and can be run. */
export interface DrizzleExecutable<out A> {
  execute(): DrizzleResult<A>;
}

/** The rows a `SELECT *` over `TTable` yields. */
export type DrizzleRows<TTable extends Table> = Array<TTable["$inferSelect"]>;

/**
 * A `SELECT` yielding `TRow`s, with its `WHERE` already applied: it can still be
 * narrowed by `limit`/`orderBy`, or run as-is.
 */
export interface DrizzleRowSelectFiltered<out TRow> extends DrizzleExecutable<Array<TRow>> {
  limit(limit: number): DrizzleExecutable<Array<TRow>>;
  orderBy(...columns: Array<SQLWrapper>): DrizzleExecutable<Array<TRow>>;
}

/** A `SELECT` yielding `TRow`s, before any `WHERE`. */
export interface DrizzleRowSelectFrom<out TRow> extends DrizzleRowSelectFiltered<TRow> {
  where(where: SQL | undefined): DrizzleRowSelectFiltered<TRow>;
}

/** A `SELECT *` over `TTable` with its `WHERE` already applied. */
export interface DrizzleSelectFiltered<TTable extends Table> extends DrizzleRowSelectFiltered<
  TTable["$inferSelect"]
> {}

/** A `SELECT * ... FROM table`, before any `WHERE`. */
export interface DrizzleSelectFrom<TTable extends Table> extends DrizzleRowSelectFrom<
  TTable["$inferSelect"]
> {}

/** The value `db.select()` returns. */
export interface DrizzleSelectBuilder {
  from<TTable extends Table>(table: TTable): DrizzleSelectFrom<TTable>;
}

/**
 * The columns a projected `SELECT` names, keyed by what the caller wants them
 * called in the result.
 */
export type DrizzleSelectFields = Readonly<Record<string, Column>>;

/**
 * The row a projected `SELECT` over `TFields` yields — drizzle's own
 * `InferColumnsDataTypes`, which reads each column's `data` and nullability
 * straight off the column object.
 */
export type DrizzleSelected<TFields extends DrizzleSelectFields> = InferColumnsDataTypes<TFields>;

/**
 * The value `db.select(fields)` returns.
 *
 * Projecting by column rather than by table is what lets one store serve tables
 * whose column names it does not know: the result is keyed by the store's own
 * field names whatever the columns are called, and typed from the columns
 * themselves. See `Columns.ts`.
 */
export interface DrizzleFieldsSelectBuilder<TFields extends DrizzleSelectFields> {
  from(table: Table): DrizzleRowSelectFrom<DrizzleSelected<TFields>>;
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
 * A `PgDatabase`, a `BaseSQLiteDatabase` (sync or async), a `MySqlDatabase` and
 * drizzle's Effect databases all implement this fragment at runtime;
 * {@link databaseLayer} and {@link effectDatabaseLayer} are what turn a concrete
 * handle into one.
 */
export interface AuthDatabase {
  select(): DrizzleSelectBuilder;
  select<TFields extends DrizzleSelectFields>(fields: TFields): DrizzleFieldsSelectBuilder<TFields>;
  insert<TTable extends Table>(table: TTable): DrizzleInsertBuilder<TTable>;
  update<TTable extends Table>(table: TTable): DrizzleUpdateBuilder<TTable>;
  delete<TTable extends Table>(table: TTable): DrizzleWhereStep;
}

// ---------------------------------------------------------------------------
// Effect-shaped handles
// ---------------------------------------------------------------------------

/**
 * A step in a drizzle query chain, named but not otherwise constrained.
 *
 * `never` in the parameter list means "whatever this method takes" — it is the
 * only parameter type every concrete drizzle signature is assignable to, and
 * unlike `any` it lets nothing through on the value side.
 */
type ChainStep<TNext> = (...args: never[]) => TNext;

/**
 * A drizzle handle whose built queries are `Effect`s rather than `Promise`s —
 * `drizzle-orm/effect-postgres`, `effect-pglite`, `effect-mysql2`,
 * `effect-sqlite-*` and the rest of drizzle's Effect drivers.
 *
 * ### Why this is shaped differently from the other doors
 *
 * {@link databaseLayer} names its argument's type exactly (`PgDatabase` and
 * friends). This door cannot: drizzle's Effect drivers live behind entrypoints
 * that only exist from drizzle `1.0`, and this package's peer range starts at
 * `0.44`, so importing `EffectPgDatabase` here would break every consumer on an
 * older drizzle. What is checked instead is the *shape of the builder chain* —
 * that `select()` yields a `from()`, that `insert()` yields a `values()`, and so
 * on, down to the `execute()` the store layer calls. The table types cannot be
 * checked at this boundary (no real drizzle handle is assignable to a signature
 * generic over drizzle's shared `Table`, which is why {@link databaseLayer} ends
 * in a cast too), but the rows and inserts the stores see are still derived from
 * the tables they were given.
 */
export interface EffectDrizzleDatabase {
  select: ChainStep<{
    from: ChainStep<{
      where: ChainStep<unknown>;
      limit: ChainStep<unknown>;
      orderBy: ChainStep<unknown>;
      execute: ChainStep<unknown>;
    }>;
  }>;
  insert: ChainStep<{ values: ChainStep<{ execute: ChainStep<unknown> }> }>;
  update: ChainStep<{ set: ChainStep<{ where: ChainStep<unknown> }> }>;
  delete: ChainStep<{ where: ChainStep<{ execute: ChainStep<unknown> }> }>;
}

// ---------------------------------------------------------------------------
// Service
// ---------------------------------------------------------------------------

/**
 * How the stores get hold of a database handle.
 *
 * `database` is run once per query rather than once per layer, so a handle that
 * is itself request-scoped can be resolved from the calling fiber's context.
 * For a fixed handle it is `Effect.succeed(handle)` and costs nothing.
 */
export interface DrizzleHandle {
  readonly database: Effect.Effect<AuthDatabase>;
}

/**
 * Tag for the drizzle database handle the stores read out of context.
 *
 * Provide it with {@link databaseLayer} (Promise-shaped drivers) or
 * {@link effectDatabaseLayer} (Effect-shaped drivers). Both accept either a
 * handle or an `Effect` yielding one.
 */
export class DrizzleDatabase extends Context.Service<DrizzleDatabase, DrizzleHandle>()(
  "@effect-auth/DrizzleDatabase",
) {}

/**
 * Normalise "a handle, or an Effect yielding one" into the per-query Effect the
 * service holds.
 *
 * The erasure is the same one {@link databaseLayer} has always made: each
 * dialect's `select().from()` is *constrained* to its own table brand
 * (`PgTable`, `SQLiteTable`, `MySqlTable`), so no dialect handle is assignable
 * to a signature generic over drizzle's shared `Table` — even though all of them
 * implement it at runtime, which is precisely what the callers' overloads have
 * just checked.
 */
const toHandle = (db: object | Effect.Effect<object>): DrizzleHandle => ({
  // SAFETY: the callers' overloads have checked `db` is (an Effect of) a drizzle
  // PostgreSQL, SQLite or MySQL handle, each of which implements `AuthDatabase`
  // at runtime; only the dialect table brands keep the types from lining up.
  database: Effect.isEffect(db)
    ? (db as Effect.Effect<AuthDatabase>)
    : Effect.succeed(db as AuthDatabase),
});

/**
 * Provide a Promise-shaped drizzle handle as {@link DrizzleDatabase}.
 *
 * Accepts any PostgreSQL, SQLite or MySQL handle — `drizzle(...)` from any
 * driver, and the transaction handle passed to `db.transaction(...)`, since
 * each dialect's transaction type extends its database type — either directly
 * or as an `Effect` that yields one.
 *
 * Passing an `Effect` defers the handle to query time: it is run once per query,
 * in the calling fiber, so a handle held in a `Context.Reference` follows the
 * request that set it. See the module docs for why that matters on Workers.
 *
 * Pair it with the tables for the *same* dialect (`Pg.tables`, `Sqlite.tables`
 * or `MySql.tables`); the store layers take those separately, so the pairing is
 * the caller's to get right.
 */
export function databaseLayer<
  TQueryResult extends PgQueryResultHKT,
  TFullSchema extends Record<string, unknown>,
  TSchema extends TablesRelationalConfig,
>(
  db:
    | PgDatabase<TQueryResult, TFullSchema, TSchema>
    | Effect.Effect<PgDatabase<TQueryResult, TFullSchema, TSchema>>,
): Layer.Layer<DrizzleDatabase>;
/**
 * Provide a Promise-shaped SQLite drizzle handle (or an `Effect` yielding one, run per
 * query) as {@link DrizzleDatabase}. The PostgreSQL overload documents the details.
 */
export function databaseLayer<
  TResultKind extends "sync" | "async",
  TRunResult,
  TFullSchema extends Record<string, unknown>,
  TSchema extends TablesRelationalConfig,
>(
  db:
    | BaseSQLiteDatabase<TResultKind, TRunResult, TFullSchema, TSchema>
    | Effect.Effect<BaseSQLiteDatabase<TResultKind, TRunResult, TFullSchema, TSchema>>,
): Layer.Layer<DrizzleDatabase>;
/**
 * Provide a Promise-shaped MySQL drizzle handle (or an `Effect` yielding one, run per
 * query) as {@link DrizzleDatabase}. The PostgreSQL overload documents the details.
 */
export function databaseLayer<
  TQueryResult extends MySqlQueryResultHKT,
  TPreparedQueryHKT extends PreparedQueryHKTBase,
  TFullSchema extends Record<string, unknown>,
  TSchema extends TablesRelationalConfig,
>(
  db:
    | MySqlDatabase<TQueryResult, TPreparedQueryHKT, TFullSchema, TSchema>
    | Effect.Effect<MySqlDatabase<TQueryResult, TPreparedQueryHKT, TFullSchema, TSchema>>,
): Layer.Layer<DrizzleDatabase>;
export function databaseLayer(db: object | Effect.Effect<object>): Layer.Layer<DrizzleDatabase> {
  return Layer.succeed(DrizzleDatabase, toHandle(db));
}

/**
 * Provide an Effect-shaped drizzle handle as {@link DrizzleDatabase}.
 *
 * This is the door for `drizzle-orm/effect-postgres` and its siblings, whose
 * queries *are* `Effect`s: the stores run them directly, so nothing in the path
 * from `Auth.SessionStore` to the database crosses a Promise boundary. See
 * {@link EffectDrizzleDatabase} for what this door can and cannot check.
 *
 * As with {@link databaseLayer}, passing an `Effect` instead of a handle defers
 * the handle to query time. With an Effect-shaped driver that is the whole
 * request-scoped-pool story: the handle lives in the request's Effect context
 * and needs no `AsyncLocalStorage` to find its way to the query.
 *
 * @example
 * ```ts
 * import * as PgDrizzle from "drizzle-orm/effect-postgres";
 *
 * const stores = Drizzle.layer(Drizzle.Pg.tables).pipe(
 *   Layer.provide(Drizzle.effectDatabaseLayer(PgDrizzle.makeWithDefaults())),
 * );
 * ```
 */
export function effectDatabaseLayer(
  db: EffectDrizzleDatabase | Effect.Effect<EffectDrizzleDatabase>,
): Layer.Layer<DrizzleDatabase> {
  return Layer.succeed(DrizzleDatabase, toHandle(db));
}
