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
import { defaultTableNames, type TableNames } from "./Schema.ts";

/**
 * Run a drizzle query, mapping any driver rejection to the `AuthError` the
 * store interfaces expose while preserving the underlying cause.
 *
 * `label` names the operation (`"session.get"`, `"identifier.create"`, ...) and
 * shows up verbatim in the error message, so a failure points at the call site
 * without a stack trace.
 *
 * @internal
 */
export const run = <A>(label: string, query: () => Promise<A>): Effect.Effect<A, Auth.AuthError> =>
  Effect.tryPromise({
    try: query,
    catch: (cause) => new Auth.AuthError({ message: `drizzle ${label} failed`, cause }),
  });

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
