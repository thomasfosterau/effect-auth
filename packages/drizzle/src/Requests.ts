/**
 * A batched, `Effect.request`-driven read interface over the same three tables
 * the stores use.
 *
 * The store layers implement effect-auth's service contracts: one call, one
 * query, ordered exactly as the caller wrote it. That is the right shape for
 * the auth flows themselves, which read one session or one user at a time.
 *
 * Application code often has the opposite shape — a page that resolves twenty
 * users, or a list that asks "does this identifier exist?" once per row.
 * {@link AuthRequests} exposes those reads as Effect `Request`s backed by
 * `RequestResolver`s: concurrent lookups collected in the same batch window
 * collapse into one `WHERE ... IN (...)` query, and repeats of the same lookup
 * inside a batch collapse into one row read.
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
 *
 * ### Why a layer
 *
 * Effect batches per **resolver instance**, so the resolvers have to be shared
 * for anything to be batched at all. {@link layer} builds them once against the
 * ambient {@link DrizzleDatabase} and hands them out as a service; the
 * constructors below read that service back out of context, which is why each
 * returns an `Effect` requiring {@link AuthRequests}.
 *
 * ### What this is not
 *
 * There is no write path here and no cache by default: results live only for
 * the batch window. Wrap a resolver with `RequestResolver.withCache` if you
 * want request-level memoization, and remember that a cached auth read is a
 * stale auth read — bound its lifetime deliberately.
 */

import { Context, Effect, Layer, RequestResolver } from "effect";
import type * as Auth from "@thomasfosterau/effect-auth";
import type { DrizzleDatabase } from "./Database.ts";
import * as IdentifierStore from "./IdentifierStore.ts";
import { tables as defaultTables } from "./PgSchema.ts";
import type { Tables } from "./Schema.ts";
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
  tables: Tables = defaultTables,
): Effect.Effect<typeof AuthRequests.Service, never, DrizzleDatabase> =>
  Effect.gen(function* () {
    return {
      session: yield* SessionStore.makeResolver(tables),
      user: yield* UserStore.makeResolver(tables),
      identifierByValue: yield* IdentifierStore.makeByValueResolver(tables),
      identifiersByUser: yield* IdentifierStore.makeByUserResolver(tables),
    } satisfies typeof AuthRequests.Service;
  });

/**
 * The batched read interface, on top of {@link DrizzleDatabase}.
 *
 * Independent of the store layers: provide either, or both. Batching is scoped
 * to this layer's lifetime, since that is what owns the resolver instances.
 */
export const layer = (
  tables: Tables = defaultTables,
): Layer.Layer<AuthRequests, never, DrizzleDatabase> => Layer.effect(AuthRequests, make(tables));

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
