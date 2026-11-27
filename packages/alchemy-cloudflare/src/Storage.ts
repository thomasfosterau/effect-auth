/**
 * Wiring: the bound D1 client, through {@link D1Client.layer}, to a `SqlClient`
 * and every `@thomasfosterau/effect-auth/sql` store. There are no D1-specific
 * stores.
 */

import type { QueryDatabaseClient } from "@alchemy.run/cloudflare/D1/QueryDatabase";
import type { RuntimeContext } from "alchemy/RuntimeContext";
import * as Effect from "effect/Effect";
import * as Layer from "effect/Layer";
import * as Sql from "@thomasfosterau/effect-auth/sql";
import type * as Auth from "@thomasfosterau/effect-auth";
import * as D1Client from "./D1Client.ts";

/** Every effect-auth store `@thomasfosterau/effect-auth/sql` implements. */
export type AuthStores = Layer.Success<typeof Sql.layer>;

/**
 * Every effect-auth store, backed by the D1 database that
 * `Cloudflare.D1.QueryDatabase(database)` binds.
 *
 * Provide it once and the auth stack (SessionService, EmailPasswordService,
 * OAuth, WebAuthn, MagicLink, EmailOTP, MultiFactor, ...) has persistence. It
 * needs the `RuntimeContext` of the Worker or Durable Object event it is built
 * in, which Alchemy provides to every handler.
 *
 * @example
 * ```ts
 * import * as AuthD1 from "@thomasfosterau/effect-auth-alchemy-cloudflare";
 *
 * const db = yield* Cloudflare.D1.QueryDatabase(AuthDatabase);
 * // in a handler:
 * yield* handle(request).pipe(Effect.provide(AuthD1.Storage.layer(db)));
 * ```
 */
export const layer = (
  database: QueryDatabaseClient,
): Layer.Layer<AuthStores, never, RuntimeContext> =>
  Sql.layer.pipe(Layer.provide(D1Client.layer({ db: database })));

/**
 * Apply the effect-auth schema to a D1 database.
 *
 * The DDL is `@thomasfosterau/effect-auth/sql`'s — the same statements every
 * other SQL deployment runs — and every statement is `IF NOT EXISTS`, so this
 * is safe to run on each deploy or cold start. Inside an Alchemy program,
 * declare the {@link "./AuthSchema.ts" | AuthSchema} action instead and let
 * the engine run it on deploy.
 */
export const migrate = (
  database: QueryDatabaseClient,
): Effect.Effect<void, Auth.Errors.AuthError, RuntimeContext> =>
  Sql.migrate.pipe(Effect.provide(D1Client.layer({ db: database })));

/**
 * Delete every expired row from a D1 database, through
 * `@thomasfosterau/effect-auth/sql`'s `purgeExpired` (which lists them).
 *
 * Nothing else deletes them, so schedule this from the Worker (a cron
 * trigger's `scheduled` handler) to keep those tables bounded.
 */
export const purgeExpired = (
  database: QueryDatabaseClient,
): Effect.Effect<Sql.PurgeExpiredResult, Auth.Errors.AuthError, RuntimeContext> =>
  Sql.purgeExpired.pipe(Effect.provide(D1Client.layer({ db: database })));
