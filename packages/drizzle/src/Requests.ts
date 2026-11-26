/**
 * Batched reads over the stores' tables for application code: concurrent
 * `Effect.request`s in one batch window collapse into one `WHERE … IN (…)`.
 * {@link layer} builds the shared resolvers, since Effect batches per resolver
 * instance. There is no write path and no cache.
 *
 * @example
 * ```ts
 * import { Effect, Layer } from "effect";
 * import * as Drizzle from "@thomasfosterau/effect-auth-drizzle";
 *
 * const program = Effect.forEach(userIds, Drizzle.Requests.getUser, {
 *   concurrency: "unbounded",
 * }); // one SELECT ... WHERE id IN (...), however many ids
 *
 * program.pipe(
 *   Effect.provide(
 *     Drizzle.Requests.layer().pipe(Layer.provide(Drizzle.databaseLayer(db))),
 *   ),
 * );
 * ```
 */

import { Context, Effect, Layer, RequestResolver } from "effect";
import type * as Auth from "@thomasfosterau/effect-auth";
import type { SchemaInput } from "./Columns.ts";
import type { DrizzleDatabase } from "./Database.ts";
import * as IdentifierStore from "./IdentifierStore.ts";
import { tables as defaultTables } from "./PgSchema.ts";
import * as SessionStore from "./SessionStore.ts";
import * as UserStore from "./UserStore.ts";

// ---------------------------------------------------------------------------
// Service
// ---------------------------------------------------------------------------

/**
 * The shared resolvers behind the request constructors in this module.
 */
export class AuthRequests extends Context.Service<
  AuthRequests,
  {
    readonly session: RequestResolver.RequestResolver<SessionStore.GetSession>;
    readonly user: RequestResolver.RequestResolver<UserStore.UserRequest>;
    readonly identifierByValue: RequestResolver.RequestResolver<IdentifierStore.GetIdentifierByValue>;
    readonly identifiersByUser: RequestResolver.RequestResolver<IdentifierStore.ListIdentifiersByUser>;
  }
>()("@effect-auth/DrizzleRequests") {}

/** Build the resolver set over the ambient {@link DrizzleDatabase}. */
export const make = (
  schema: SchemaInput = defaultTables,
): Effect.Effect<typeof AuthRequests.Service, never, DrizzleDatabase> =>
  Effect.gen(function* () {
    return {
      session: yield* SessionStore.makeResolver(schema),
      user: yield* UserStore.makeResolver(schema),
      identifierByValue: yield* IdentifierStore.makeByValueResolver(schema),
      identifiersByUser: yield* IdentifierStore.makeByUserResolver(schema),
    } satisfies typeof AuthRequests.Service;
  });

/**
 * The batched read interface, on top of {@link DrizzleDatabase}.
 *
 * Independent of the store layers: provide either, or both. Batching is scoped
 * to this layer's lifetime, since that is what owns the resolver instances.
 */
export const layer = (
  schema: SchemaInput = defaultTables,
): Layer.Layer<AuthRequests, never, DrizzleDatabase> => Layer.effect(AuthRequests, make(schema));

// ---------------------------------------------------------------------------
// Constructors
// ---------------------------------------------------------------------------

/**
 * Read a session by id (the SHA-256 hash of the bearer token), batched with
 * every other concurrent session read. `null` on a miss.
 */
export const getSession = (
  id: string,
): Effect.Effect<Auth.Session | null, Auth.AuthError, AuthRequests> =>
  Effect.request<SessionStore.GetSession, never, AuthRequests>(
    new SessionStore.GetSession({ id }),
    Effect.map(AuthRequests, (requests) => requests.session),
  );

/**
 * Read a user by id, batched with every other concurrent user read. `null` on
 * a miss.
 */
export const getUser = (
  id: string,
): Effect.Effect<Auth.User | null, Auth.AuthError, AuthRequests> =>
  Effect.request<UserStore.GetUser, never, AuthRequests>(
    new UserStore.GetUser({ id }),
    Effect.map(AuthRequests, (requests) => requests.user),
  );

/**
 * Resolve an identifier by its `(type, value)` pair, batched with every other
 * concurrent pair lookup. `null` on a miss.
 */
export const getIdentifierByValue = (
  type: Auth.IdentifierType,
  value: string,
): Effect.Effect<Auth.Identifier | null, Auth.AuthError, AuthRequests> =>
  Effect.request<IdentifierStore.GetIdentifierByValue, never, AuthRequests>(
    new IdentifierStore.GetIdentifierByValue({ type, value }),
    Effect.map(AuthRequests, (requests) => requests.identifierByValue),
  );

/**
 * List a user's identifiers (oldest first), batched with every other
 * concurrent list. `[]` for a user with none.
 */
export const listIdentifiersByUser = (
  userId: string,
): Effect.Effect<ReadonlyArray<Auth.Identifier>, Auth.AuthError, AuthRequests> =>
  Effect.request<IdentifierStore.ListIdentifiersByUser, never, AuthRequests>(
    new IdentifierStore.ListIdentifiersByUser({ userId }),
    Effect.map(AuthRequests, (requests) => requests.identifiersByUser),
  );
