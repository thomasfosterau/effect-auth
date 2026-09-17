/**
 * The one composite layer this package ships: every drizzle-backed store at
 * once.
 *
 * It lives apart from the three store modules because it belongs to none of
 * them — each store module owns its own `layer`, and this is the bundle. The
 * batched read interface is deliberately *not* part of it; provide
 * `Requests.layer()` alongside when an application wants it.
 */

import { Layer } from "effect";
import type * as Auth from "@thomasfosterau/effect-auth";
import type { SchemaInput } from "./Columns.ts";
import type { DrizzleDatabase } from "./Database.ts";
import * as IdentifierStore from "./IdentifierStore.ts";
import { tables as defaultTables } from "./PgSchema.ts";
import * as SessionStore from "./SessionStore.ts";
import * as UserStore from "./UserStore.ts";

/**
 * Every drizzle-backed store in one layer. Provide it together with a
 * {@link DrizzleDatabase} layer and the session/sign-in path (session
 * validation, credential lookup, identifier resolution) has persistence.
 *
 * `schema` defaults to the PostgreSQL tables under their `effect_auth_*` names;
 * pass `Sqlite.tables` or `MySql.tables` (or a `defineTables(...)` result from
 * any of the three) to match the handle you provided, or a `defineSchema(...)`
 * mapping to run the stores against tables this package did not define.
 *
 * Stores beyond these three — OAuth accounts, WebAuthn credentials, rate
 * limits, and the rest — are not covered here yet; use
 * `@thomasfosterau/effect-auth-sql` or a `KeyValueStore`-backed layer from
 * core for those.
 *
 * @example
 * ```ts
 * const stores = layer(Pg.defineTables({ sessions: "app_sessions" }));
 *
 * // Or, against an application's own tables:
 * const adopted = layer(defineSchema({ sessions: { table, columns }, ... }));
 * ```
 */
export const layer = (
  schema: SchemaInput = defaultTables,
): Layer.Layer<Auth.SessionStore | Auth.UserStore | Auth.IdentifierStore, never, DrizzleDatabase> =>
  Layer.mergeAll(
    SessionStore.layer(schema),
    UserStore.layer(schema),
    IdentifierStore.layer(schema),
  );
