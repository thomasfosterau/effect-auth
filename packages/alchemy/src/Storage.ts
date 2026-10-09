/**
 * Wiring: a Cloudflare D1 binding → a `SqlClient` → every effect-auth store.
 *
 * There are no D1-flavoured store implementations in this package. The stores
 * come from `@thomasfosterau/effect-auth-sql`, which implements every
 * effect-auth storage interface against `effect/sql`'s `SqlClient`
 * with DDL that is valid on SQLite (and therefore D1) and Postgres.
 * All this module does is build the client with {@link D1Client.layer} and
 * provide it to those stores.
 */

import { Effect, Layer } from "effect";
import * as Sql from "@thomasfosterau/effect-auth-sql";
import type * as Auth from "@thomasfosterau/effect-auth";
import * as D1Client from "./D1Client.ts";

export type { D1Database } from "./D1Client.ts";

/** Every effect-auth store `@thomasfosterau/effect-auth-sql` implements. */
export type AuthStores = Layer.Success<typeof Sql.layer>;

/**
 * Every effect-auth store, backed by a Cloudflare D1 binding.
 *
 * Provide it once and the auth stack (SessionService, EmailPasswordService,
 * OAuth, WebAuthn, MagicLink, EmailOTP, MultiFactor, ...) has persistence.
 *
 * @example
 * ```ts
 * import * as D1 from "@thomasfosterau/effect-auth-alchemy";
 *
 * const AppLayer = Auth.layer.pipe(Layer.provide(D1.layer(env.DB)));
 * ```
 */
export const layer = (database: D1Client.D1Database): Layer.Layer<AuthStores> =>
  Sql.layer.pipe(Layer.provide(D1Client.layer({ db: database })));

/**
 * Apply the effect-auth schema to a D1 database.
 *
 * The DDL is `@thomasfosterau/effect-auth-sql`'s — the same statements every
 * other SQL deployment runs — and every statement is `IF NOT EXISTS`, so this
 * is safe to run on each deploy or cold start. Inside an Alchemy program,
 * declare the {@link "./AuthSchema.ts" | AuthSchema} resource instead and let
 * the engine run it.
 */
export const migrate = (database: D1Client.D1Database): Effect.Effect<void, Auth.AuthError> =>
  Sql.migrate.pipe(Effect.provide(D1Client.layer({ db: database })));
