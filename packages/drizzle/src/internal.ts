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

import { Effect } from "effect";
import * as Auth from "@thomasfosterau/effect-auth";
import type { AuthDatabase, DrizzleHandle, DrizzleResult } from "./Database.ts";
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
 * Fill in the `effect_auth_*` defaults for any table name the caller omitted.
 *
 * @internal
 */
export const resolveTableNames = (names?: Partial<TableNames>): TableNames => ({
  sessions: names?.sessions ?? defaultTableNames.sessions,
  users: names?.users ?? defaultTableNames.users,
  identifiers: names?.identifiers ?? defaultTableNames.identifiers,
});
