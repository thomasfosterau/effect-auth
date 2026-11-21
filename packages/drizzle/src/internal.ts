/**
 * Internal plumbing shared by every store and schema module in this package.
 *
 * Nothing here is re-exported from `index.ts`: it is the seam the store modules,
 * their request resolvers and the three dialect schemas have in common, kept in
 * a single place so the `AuthError` contract and the table-name defaults cannot
 * drift between them.
 *
 * @internal
 */

import { Effect, Exit, HashMap } from "effect";
import * as Arr from "effect/Array";
import * as Option from "effect/Option";
import * as Schema from "effect/Schema";
import * as SchemaGetter from "effect/SchemaGetter";
import * as Auth from "@thomasfosterau/effect-auth";
import type { SQL, Table } from "drizzle-orm";
import type {
  AuthDatabase,
  DrizzleHandle,
  DrizzleResult,
  DrizzleSelected,
  DrizzleSelectFields,
} from "./Database.ts";
import { defaultTableNames, type TableNames } from "./Schema.ts";

/**
 * Run a drizzle query, mapping any driver rejection to the `AuthError` the
 * store interfaces expose while preserving the underlying cause.
 *
 * `label` names the operation (`"session.get"`, `"identifier.create"`, ...) and
 * shows up verbatim in the error message, so a failure points at the call site
 * without a stack trace.
 *
 * A built query is a `Promise` on the classic drivers and an `Effect` on
 * drizzle's Effect drivers; both are handled here so the store code is written
 * once. The Effect branch runs the driver's own Effect directly — no
 * `Promise` round trip, no fiber hand-off.
 *
 * @internal
 */
export const run = <A>(
  label: string,
  query: () => DrizzleResult<A>,
): Effect.Effect<A, Auth.AuthError> => {
  const toAuthError = (cause: unknown): Auth.AuthError =>
    new Auth.AuthError({ message: `drizzle ${label} failed`, cause });

  const execute = (result: DrizzleResult<A>): Effect.Effect<A, Auth.AuthError> =>
    Effect.isEffect(result)
      ? Effect.mapError(result, toAuthError)
      : Effect.tryPromise({ try: () => result, catch: toAuthError });

  // Building the query can itself throw (a malformed `WHERE`, a column the
  // handle does not know); that is the same class of failure as a rejection
  // and surfaces the same way.
  return Effect.flatten(Effect.try({ try: () => execute(query()), catch: toAuthError }));
};

/**
 * Bind a {@link DrizzleHandle} into the `run`-shaped helper the stores use.
 *
 * The handle is resolved *per query* rather than captured once, which is what
 * lets an application hand over a request-scoped connection: `build` runs in the
 * calling fiber, so a handle held in a `Context.Reference` is the one that
 * fiber's request set.
 *
 * @internal
 */
export const makeQuery =
  (handle: DrizzleHandle) =>
  <A>(
    label: string,
    build: (db: AuthDatabase) => DrizzleResult<A>,
  ): Effect.Effect<A, Auth.AuthError> =>
    Effect.flatMap(handle.database, (db) => run(label, () => build(db)));

/** The per-query runner {@link makeQuery} produces. @internal */
export type Query = ReturnType<typeof makeQuery>;

/**
 * The first row of `table` matching `where`, projected onto `fields`, or
 * `null` on a miss.
 *
 * @internal
 */
export const selectOne = <TFields extends DrizzleSelectFields>(
  query: Query,
  label: string,
  fields: TFields,
  table: Table,
  where: SQL,
): Effect.Effect<DrizzleSelected<TFields> | null, Auth.AuthError> =>
  query(label, (db) => db.select(fields).from(table).where(where).limit(1).execute()).pipe(
    Effect.map((rows) => rows[0] ?? null),
  );

/**
 * One entry of a batch of by-id lookups: the request carries the id, and the
 * entry is completed with the found value or `null`.
 *
 * @internal
 */
export interface ByIdEntry<A> {
  readonly request: { readonly id: string };
  completeUnsafe(exit: Exit.Exit<A | null>): void;
}

/**
 * Answer a batch of by-id lookups with one query: dedupe the requested ids,
 * fetch their rows with `fetchRows`, and complete each entry with its row's
 * value, or `null` on a miss.
 *
 * @internal
 */
export const completeById = <Row extends { readonly id: string }, A, E>(
  entries: ReadonlyArray<ByIdEntry<A>>,
  fetchRows: (ids: Array<string>) => Effect.Effect<ReadonlyArray<Row>, E>,
  toValue: (row: Row) => A,
): Effect.Effect<void, E> =>
  Effect.map(fetchRows(Arr.dedupe(entries.map((entry) => entry.request.id))), (rows) => {
    const byId = HashMap.fromIterable(rows.map((row) => [row.id, toValue(row)] as const));
    Arr.forEach(entries, (entry) =>
      entry.completeUnsafe(Exit.succeed(Option.getOrNull(HashMap.get(byId, entry.request.id)))),
    );
  });

/**
 * Fill in the `effect_auth_*` defaults for any table name the caller omitted.
 *
 * @internal
 */
export const resolveTableNames = (names?: Partial<TableNames>): TableNames => ({
  ...defaultTableNames,
  ...names,
});

/** One driver's report of the rows a statement touched. */
const AffectedRowsHeader = Schema.Union([
  Schema.Struct({ affectedRows: Schema.Finite }),
  Schema.Struct({ rowCount: Schema.Finite }),
  Schema.Struct({ changes: Schema.Finite }),
  Schema.Struct({ rowsAffected: Schema.Finite }),
  Schema.Struct({ meta: Schema.Struct({ changes: Schema.Finite }) }),
]);

/**
 * The number of rows a `DELETE` / `UPDATE` touched, decoded from whatever the
 * driver's `execute()` resolved to. The shapes differ by driver: PGlite and
 * mysql2 carry `affectedRows` (mysql2 in a `[ResultSetHeader, …]` pair),
 * node-postgres `rowCount`, better-sqlite3 `changes`, libsql `rowsAffected`
 * and D1 `meta.changes`.
 */
const AffectedRows = Schema.Union([
  AffectedRowsHeader,
  Schema.TupleWithRest(Schema.Tuple([AffectedRowsHeader]), [Schema.Unknown]),
]).pipe(
  Schema.decodeTo(Schema.Finite, {
    decode: SchemaGetter.transform((result) => {
      const header = Array.isArray(result) ? result[0] : result;
      return "affectedRows" in header
        ? header.affectedRows
        : "rowCount" in header
          ? header.rowCount
          : "changes" in header
            ? header.changes
            : "rowsAffected" in header
              ? header.rowsAffected
              : header.meta.changes;
    }),
    encode: SchemaGetter.forbidden(() => "affected-row counts are read, never written"),
  }),
);

/**
 * Run a write and count the rows it touched, from its driver result, for a
 * compare-and-set that cannot use `RETURNING` (MySQL has none). A driver
 * that reports no count fails as `AuthError` rather than let the caller
 * guess.
 *
 * @internal
 */
export const affectedRows = <E>(
  label: string,
  write: Effect.Effect<unknown, E>,
): Effect.Effect<number, E | Auth.AuthError> =>
  Effect.flatMap(write, (result) =>
    Effect.fromOption(Schema.decodeUnknownOption(AffectedRows)(result)).pipe(
      Effect.mapError(
        () =>
          new Auth.AuthError({
            message: `drizzle ${label}: the driver reported no affected-row count`,
          }),
      ),
    ),
  );
