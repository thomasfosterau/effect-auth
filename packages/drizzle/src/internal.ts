/**
 * Internal plumbing shared by every store module in this package.
 *
 * Nothing here is re-exported from `index.ts`: it is the one seam the three
 * store modules and their request resolvers have in common, kept in a single
 * place so the `AuthError` contract cannot drift between them.
 *
 * @internal
 */

import { Effect } from "effect";
import * as Auth from "@thomasfosterau/effect-auth";

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
