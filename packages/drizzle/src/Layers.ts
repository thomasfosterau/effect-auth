/**
 * The one composite layer this package ships: every drizzle-backed store at
 * once.
 *
 * It lives apart from the three store modules because it belongs to none of
 * them — each store module owns its own `*StoreLayer`, and this is the bundle.
 * The batched read interface is deliberately *not* part of it; provide
 * `requestsLayer()` alongside when an application wants it.
 */

import { Layer } from "effect";
import type * as Auth from "@thomasfosterau/effect-auth";
import type { DrizzleDatabase } from "./Database.ts";
import { identifierStoreLayer } from "./IdentifierStore.ts";
import type { Tables } from "./Schema.ts";
import { tables as defaultTables } from "./Schema.ts";
import { sessionStoreLayer } from "./SessionStore.ts";
import { userStoreLayer } from "./UserStore.ts";

/**
 * Every drizzle-backed store in one layer. Provide it together with a
 * {@link DrizzleDatabase} layer and the session/sign-in path (session
 * validation, credential lookup, identifier resolution) has persistence.
 *
 * Stores beyond these three — OAuth accounts, WebAuthn credentials, rate
 * limits, and the rest — are not covered here yet; use
 * `@thomasfosterau/effect-auth-sql` or a `KeyValueStore`-backed layer from
 * core for those.
 *
 * @example
 * ```ts
 * const stores = layer(defineTables({ sessions: "app_sessions" }));
 * ```
 */
export const layer = (
  tables: Tables = defaultTables,
): Layer.Layer<Auth.SessionStore | Auth.UserStore | Auth.IdentifierStore, never, DrizzleDatabase> =>
  Layer.mergeAll(sessionStoreLayer(tables), userStoreLayer(tables), identifierStoreLayer(tables));
