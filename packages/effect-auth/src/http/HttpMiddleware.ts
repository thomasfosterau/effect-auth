/**
 * `HttpApiMiddleware` for any `HttpApi`: {@link layer} implements
 * `AuthMiddleware` (the session cookie or an `Authorization` bearer; `401` when
 * absent or invalid, a logged `500` on a store fault) and {@link optionalLayer}
 * implements `OptionalAuthMiddleware`. Handlers read the re-exported
 * `SessionContext` services.
 *
 * @example Attaching required auth to a group
 * ```ts
 * import assert from "node:assert/strict"
 * import { Effect, FileSystem, Layer, Option, Path } from "effect"
 * import * as Schema from "effect/Schema"
 * import { Etag, HttpPlatform, HttpRouter } from "effect/http"
 * import { HttpApi, HttpApiBuilder, HttpApiEndpoint, HttpApiGroup } from "effect/http-api"
 * import { AuthMiddleware, CurrentUser, layer as authLayer } from "@thomasfosterau/effect-auth/http"
 * import {
 *   Hooks,
 *   SessionService,
 *   SessionStore,
 *   UserStore,
 *   type Session,
 *   type User,
 * } from "@thomasfosterau/effect-auth"
 *
 * const ProfileSchema = Schema.Struct({ id: Schema.String })
 *
 * // In-memory stores for the session service. A real app backs these with its database.
 * const sessions = new Map<string, Session>()
 * const users = new Map<string, User>()
 * const storeLayers = Layer.mergeAll(
 *   Layer.succeed(SessionStore, {
 *     create: (session) => Effect.sync(() => (sessions.set(session.id, session), session)),
 *     get: (id) => Effect.sync(() => Option.fromUndefinedOr(sessions.get(id))),
 *     update: (session) =>
 *       Effect.sync(() => (sessions.has(session.id) && sessions.set(session.id, session), session)),
 *     touch: (id, touch) =>
 *       Effect.sync(() => {
 *         const session = sessions.get(id)
 *         if (session === undefined || session.expiresAt < touch.lastActivityAt) return Option.none()
 *         const touched = { ...session, ...touch }
 *         sessions.set(id, touched)
 *         return Option.some(touched)
 *       }),
 *     delete: (id) => Effect.sync(() => void sessions.delete(id)),
 *     deleteByUserId: (userId) =>
 *       Effect.sync(() => {
 *         for (const [id, session] of sessions) if (session.userId === userId) sessions.delete(id)
 *       }),
 *     listByUserId: (userId) =>
 *       Effect.sync(() => [...sessions.values()].filter((s) => s.userId === userId)),
 *   }),
 *   Layer.succeed(UserStore, { get: (id) => Effect.sync(() => Option.fromUndefinedOr(users.get(id))) }),
 * )
 *
 * // Stands in for the services the app provides (SessionService, Hooks, ...).
 * const myServiceLayer = SessionService.layer({
 *   sessionExpiresIn: { activePeriod: 7 * 86_400_000, idlePeriod: 86_400_000 },
 * }).pipe(Layer.provideMerge(Layer.mergeAll(storeLayers, Hooks.Default)))
 *
 * // 1. Define API group – mark endpoints that need auth
 * const ProfileGroup = HttpApiGroup.make("profile").add(
 *   HttpApiEndpoint.get("getProfile", "/profile", { success: ProfileSchema }).middleware(
 *     AuthMiddleware,
 *   ),
 * )
 *
 * const MyApi = HttpApi.make("MyApi").add(ProfileGroup)
 *
 * // 2. Implement the handler – CurrentUser is available in context
 * const ProfileGroupLayer = HttpApiBuilder.group(MyApi, "profile", (handlers) =>
 *   handlers.handle("getProfile", () =>
 *     Effect.gen(function* () {
 *       const user = yield* CurrentUser
 *       return { id: user.id }
 *     }),
 *   ),
 * )
 *
 * // 3. Wire up the middleware layer alongside your service layer
 * const AppLayer = HttpApiBuilder.layer(MyApi).pipe(
 *   Layer.provide(ProfileGroupLayer),
 *   Layer.provide(authLayer()),
 *   Layer.provide(myServiceLayer), // must provide SessionService, Hooks, …
 *   Layer.provide(
 *     Layer.mergeAll(
 *       Path.layer,
 *       Etag.layerWeak,
 *       HttpPlatform.layer.pipe(Layer.provide(FileSystem.layerNoop({}))),
 *       FileSystem.layerNoop({}),
 *     ),
 *   ),
 * )
 *
 * // Sign a user in and serve the app in-process.
 * const program = Effect.gen(function* () {
 *   const now = new Date()
 *   users.set("u-1", { id: "u-1", name: "Ada", createdAt: now, updatedAt: now, attributes: {} })
 *   const sessionService = yield* SessionService
 *   // The raw token is the session id; the store keeps only its hash.
 *   return (yield* sessionService.createSession("u-1")).token
 * }).pipe(Effect.provide(myServiceLayer))
 *
 * const token = await Effect.runPromise(program)
 * const { handler, dispose } = HttpRouter.toWebHandler(AppLayer)
 * try {
 *   const signedIn = await handler(
 *     new Request("http://localhost/profile", { headers: { authorization: `Bearer ${token}` } }),
 *   )
 *   assert.equal(signedIn.status, 200)
 *   assert.deepEqual(await signedIn.json(), { id: "u-1" })
 *
 *   const anonymous = await handler(new Request("http://localhost/profile"))
 *   assert.equal(anonymous.status, 401)
 * } finally {
 *   await dispose()
 * }
 * ```
 */

import { Cause, Clock, Effect, Layer, Redacted } from "effect";
import * as Option from "effect/Option";
import { HttpApiMiddleware, HttpApiSecurity } from "effect/http-api";
import { HttpServerRequest } from "effect/http";
import { Hooks } from "../Hooks.ts";
import { SessionService } from "../SessionService.ts";
import { CurrentPrincipal, CurrentCredential } from "../Authorizer.ts";
import {
  CurrentSession,
  CurrentUser,
  MaybeCurrentSession,
  principalOf,
} from "../SessionContext.ts";
import * as S from "./HttpApiSchema.ts";
import type * as Types from "../Types.ts";
import { sessionCredentialClass } from "../Types.ts";
import {
  dataCookieName,
  internalServerError,
  resolveCookieConfig,
  sessionIdFromRequest,
  sessionValidationFailure,
  type CookieConfig,
  type ResolvedCookieConfig,
} from "./HttpServer.ts";
import type { AuthError } from "../Errors.ts";
import { decodeSessionCacheCookie, sessionCacheGateAttributes } from "../SessionCookieCache.ts";
import * as PlatformCrypto from "../PlatformCrypto.ts";
import { hashToken } from "../TokenHash.ts";

// =============================================================================
// Context services
// =============================================================================

/**
 * The session-context services, re-exported from `SessionContext.ts`.
 *
 * They are declared there rather than here because *providing* a resolved
 * session is not an HTTP concern: the same tags are filled by the middleware
 * below, by `SessionContext.authenticatedLayer` at a non-HTTP edge, and by a
 * test harness. Re-exported so `Http.CurrentUser` keeps resolving.
 *
 * - `CurrentSession` / `CurrentUser` — provided by `AuthMiddleware`.
 * - `MaybeCurrentSession` — `Option<SessionWithUser>`, provided by **both**
 *   middlewares, and the service read-path code should depend on.
 *
 * @since 0.1.0
 * @category context
 */
export { CurrentSession, CurrentUser, MaybeCurrentSession } from "../SessionContext.ts";

// =============================================================================
// HttpApiSecurity definitions (for OpenAPI advertising)
// =============================================================================

/**
 * `HttpApiSecurity` describing the session cookie scheme.
 *
 * The cookie name shown in the OpenAPI spec defaults to `"conduit_session"`.
 * Construct your own with `HttpApiSecurity.apiKey({ key: yourName, in: "cookie" })`
 * when your cookie name differs.
 *
 * @since 0.1.0
 * @category security
 */
export const sessionCookieSecurity: HttpApiSecurity.ApiKey = HttpApiSecurity.apiKey({
  key: "conduit_session",
  in: "cookie",
});

/**
 * `HttpApiSecurity` describing the `Authorization: Bearer` scheme.
 *
 * @since 0.1.0
 * @category security
 */
export const bearerTokenSecurity: HttpApiSecurity.Http = HttpApiSecurity.bearer;

// Security scheme record attached to AuthMiddleware (drives OpenAPI output).
// Key names become OpenAPI securityScheme names.
const _authSecurity = {
  conduit_session: sessionCookieSecurity,
  bearer: bearerTokenSecurity,
} as const;

// =============================================================================
// AuthMiddleware — required auth
// =============================================================================

/**
 * Required-auth `HttpApiMiddleware` tag.
 *
 * Attach to an `HttpApiGroup` or `HttpApiEndpoint` with `.middleware(AuthMiddleware)`.
 * Reads the session from the request (session cookie or
 * `Authorization: Bearer/Token` header), validates it via `SessionService`
 * (honoring the signed cookie cache), and provides `CurrentSession`,
 * `CurrentUser`, `CurrentPrincipal` (`User::"<user.id>"`) and
 * `CurrentCredential` (the class the session was issued with,
 * `sessionCredentialClass`, whichever carrier presented the token) to the
 * downstream handler.
 *
 * Fails with `Unauthorized` (HTTP 401) when the session is absent, expired, or
 * invalid, and with a logged `InternalServerError` (HTTP 500) when the session
 * or user store faults.
 *
 * It also provides `MaybeCurrentSession` — always `Option.some` here, since
 * this middleware only reaches the handler when a session resolved. That is
 * what lets one effect written against the read-path service run unchanged
 * under this middleware, under `OptionalAuthMiddleware`, and under
 * `SessionContext.layer` at a non-HTTP edge.
 *
 * The tag carries `HttpApiSecurity` definitions for the cookie and Bearer
 * schemes so the derived OpenAPI spec advertises both.
 *
 * Requires `SessionService` and `Hooks` in the application's service context.
 *
 * `requires` is intentionally per-request, not resolved at Layer construction:
 * an `HttpApiMiddleware` runs once per incoming request and needs the
 * request-scoped framework services (`HttpServerRequest`,
 * `ParsedSearchParams`, `RouteContext`) plus the ambient `SessionService`/
 * `Hooks` to validate that specific request's session — there is no
 * construction-time value to resolve them to.
 *
 * @effect-expect-leaking SessionService
 * @effect-expect-leaking Hooks
 * @effect-expect-leaking HttpServerRequest
 * @effect-expect-leaking ParsedSearchParams
 * @effect-expect-leaking RouteContext
 *
 * @since 0.1.0
 * @category middleware
 */
export class AuthMiddleware extends HttpApiMiddleware.Service<
  AuthMiddleware,
  {
    requires: SessionService | Hooks;
    provides:
      | CurrentSession
      | CurrentUser
      | MaybeCurrentSession
      | CurrentPrincipal
      | CurrentCredential;
  }
>()("@effect-auth/AuthMiddleware", {
  error: [S.UnauthorizedError, S.InternalError],
  security: _authSecurity,
}) {}

// =============================================================================
// OptionalAuthMiddleware — optional auth
// =============================================================================

/**
 * Optional-auth `HttpApiMiddleware` tag.
 *
 * Attach to an `HttpApiGroup` or `HttpApiEndpoint` with
 * `.middleware(OptionalAuthMiddleware)`. Behaves like `AuthMiddleware` but
 * does not refuse an anonymous caller: when no valid session is found, it
 * provides `MaybeCurrentSession` with `Option.none()`. A session or user store
 * fault is a logged `500`, unless `optionalLayer`'s `onDegraded` is
 * given.
 *
 * When (and only when) a session resolves, `CurrentPrincipal`
 * (`User::"<user.id>"`) and `CurrentCredential` are provided too. Neither is
 * listed in `provides`: both are conditional, and declaring them
 * unconditionally would let a handler `yield* CurrentPrincipal` and die on
 * the anonymous path. Read them with `Effect.serviceOption(CurrentPrincipal)`
 * / `Effect.serviceOption(CurrentCredential)`, which is exactly the
 * "authorize if authenticated" shape optional-auth routes want.
 *
 * Requires `SessionService` and `Hooks` in the application's service context.
 *
 * `requires` is intentionally per-request — see {@link AuthMiddleware} for why
 * this middleware's dependencies cannot be resolved at Layer construction.
 *
 * @effect-expect-leaking SessionService
 * @effect-expect-leaking Hooks
 * @effect-expect-leaking HttpServerRequest
 * @effect-expect-leaking ParsedSearchParams
 * @effect-expect-leaking RouteContext
 *
 * @since 0.1.0
 * @category middleware
 */
export class OptionalAuthMiddleware extends HttpApiMiddleware.Service<
  OptionalAuthMiddleware,
  { requires: SessionService | Hooks; provides: MaybeCurrentSession }
>()("@effect-auth/OptionalAuthMiddleware", {
  error: S.InternalError,
}) {}

/**
 * Options for {@link optionalLayer}.
 *
 * @since 0.1.0
 * @category models
 */
export interface OptionalAuthOptions {
  /**
   * Serve the request as anonymous when the session or user store faults,
   * after reporting the fault here. Without it a fault is a logged `500`:
   * a store outage never silently turns signed-in callers into
   * anonymous ones. As with `SessionResolution.resolveFailOpen`'s
   * `onDegraded`, choosing to degrade means naming where it is reported.
   */
  readonly onDegraded?: (cause: Cause.Cause<AuthError>) => Effect.Effect<void>;
}

// =============================================================================
// Internal session resolution helper
// =============================================================================

/**
 * Resolve and validate the session from the current HTTP request.
 *
 * 1. When a signed session-data cache cookie is present and valid, the
 *    session+user are returned without a store read (cache hit).
 * 2. Otherwise, the raw session token is extracted from the
 *    `Authorization: Bearer/Token` header or the session cookie, then
 *    validated against the session store.
 *
 * Returns `Option.none()` when no token is found at all.
 * Fails with `Unauthorized` when a token is present but invalid/expired, and
 * with the store's `AuthError` when the session or user store faults:
 * each middleware decides how a fault is answered, never as a `401`.
 */
const resolveSessionFromRequest = (
  request: HttpServerRequest.HttpServerRequest,
  cfg: ResolvedCookieConfig,
): Effect.Effect<
  Option.Option<Types.SessionWithUser>,
  S.Unauthorized | AuthError,
  SessionService | Hooks
> =>
  Effect.gen(function* () {
    // --- Cache path ---
    if (cfg.cache !== undefined) {
      const primaryId = sessionIdFromRequest(request, cfg);
      if (primaryId !== undefined) {
        const cached = request.cookies[dataCookieName(cfg)];
        if (cached !== undefined) {
          const gate = yield* sessionCacheGateAttributes;
          const resolved = yield* decodeSessionCacheCookie(
            cached,
            cfg.cache,
            yield* Clock.currentTimeMillis,
            yield* PlatformCrypto.provide(hashToken(primaryId)),
            gate,
          ).pipe(PlatformCrypto.provide);
          if (Option.isSome(resolved)) return resolved;
        }
      }
    }

    // --- Store path ---
    const sessionId = sessionIdFromRequest(request, cfg);
    if (sessionId === undefined) return Option.none<Types.SessionWithUser>();

    const sessionService = yield* SessionService;
    const resolved = yield* sessionService
      .validateSession(sessionId)
      .pipe(Effect.catch(sessionValidationFailure));

    return Option.some(resolved);
  });

/**
 * The requests whose `conduit_session` attempt met a store fault, so the
 * `bearer` fallback answers the same `500` rather than a `401` of its own: the
 * security runtime answers with the last scheme's failure.
 */
const faultedRequests = new WeakSet<HttpServerRequest.HttpServerRequest>();

/** The required-auth answer to a store fault: a logged `500`, never a `401`. */
const requiredAuthFault = (request: HttpServerRequest.HttpServerRequest) => (error: AuthError) =>
  Effect.sync(() => faultedRequests.add(request)).pipe(Effect.andThen(internalServerError(error)));

// =============================================================================
// Layer factories
// =============================================================================

/** The arguments the security runtime passes to `AuthMiddleware`'s handler for one scheme. */
type SchemeHandlerArgs<Scheme extends keyof AuthMiddleware["Service"]> = Parameters<
  AuthMiddleware["Service"][Scheme]
>;

/**
 * Build the `Layer` that implements `AuthMiddleware`.
 *
 * Reads the session from the request (session cookie or
 * `Authorization: Bearer/Token` header), validates it via `SessionService`
 * (honoring the signed cookie cache), and provides `CurrentSession` and
 * `CurrentUser` to downstream handlers.
 *
 * Fails with `Unauthorized` (HTTP 401) when the session is absent, expired, or
 * invalid, and with a logged `InternalServerError` (HTTP 500) when the session
 * or user store faults.
 *
 * @param config - Optional cookie configuration (name, secure, cache, …).
 *   Defaults match `HttpServer.make` defaults (`name: "conduit_session"`,
 *   `secure: true`).
 *
 * @example
 * ```ts
 * import assert from "node:assert/strict"
 * import { Effect, FileSystem, Layer, Option, Path } from "effect"
 * import * as Schema from "effect/Schema"
 * import { Etag, HttpPlatform, HttpRouter } from "effect/http"
 * import { HttpApi, HttpApiBuilder, HttpApiEndpoint, HttpApiGroup } from "effect/http-api"
 * import { AuthMiddleware, CurrentUser, layer } from "@thomasfosterau/effect-auth/http"
 * import {
 *   Hooks,
 *   SessionService,
 *   SessionStore,
 *   UserStore,
 *   type Session,
 *   type User,
 * } from "@thomasfosterau/effect-auth"
 *
 * // In-memory stores for the session service. A real app backs these with its database.
 * const sessions = new Map<string, Session>()
 * const users = new Map<string, User>()
 * const storeLayers = Layer.mergeAll(
 *   Layer.succeed(SessionStore, {
 *     create: (session) => Effect.sync(() => (sessions.set(session.id, session), session)),
 *     get: (id) => Effect.sync(() => Option.fromUndefinedOr(sessions.get(id))),
 *     update: (session) =>
 *       Effect.sync(() => (sessions.has(session.id) && sessions.set(session.id, session), session)),
 *     touch: (id, touch) =>
 *       Effect.sync(() => {
 *         const session = sessions.get(id)
 *         if (session === undefined || session.expiresAt < touch.lastActivityAt) return Option.none()
 *         const touched = { ...session, ...touch }
 *         sessions.set(id, touched)
 *         return Option.some(touched)
 *       }),
 *     delete: (id) => Effect.sync(() => void sessions.delete(id)),
 *     deleteByUserId: (userId) =>
 *       Effect.sync(() => {
 *         for (const [id, session] of sessions) if (session.userId === userId) sessions.delete(id)
 *       }),
 *     listByUserId: (userId) =>
 *       Effect.sync(() => [...sessions.values()].filter((s) => s.userId === userId)),
 *   }),
 *   Layer.succeed(UserStore, { get: (id) => Effect.sync(() => Option.fromUndefinedOr(users.get(id))) }),
 * )
 *
 * // The app's services: SessionService and Hooks.
 * const myServiceLayer = SessionService.layer({
 *   sessionExpiresIn: { activePeriod: 7 * 86_400_000, idlePeriod: 86_400_000 },
 * }).pipe(Layer.provideMerge(Layer.mergeAll(storeLayers, Hooks.Default)))
 *
 * const AccountSchema = Schema.Struct({ id: Schema.String })
 * const MyApi = HttpApi.make("MyApi").add(
 *   HttpApiGroup.make("account").add(
 *     HttpApiEndpoint.get("getAccount", "/account", { success: AccountSchema }).middleware(
 *       AuthMiddleware,
 *     ),
 *   ),
 * )
 *
 * // Stand-in for the account group handlers: the signed-in user is `CurrentUser`.
 * const myGroupLayer = HttpApiBuilder.group(MyApi, "account", (handlers) =>
 *   handlers.handle("getAccount", () =>
 *     Effect.gen(function* () {
 *       const user = yield* CurrentUser
 *       return { id: user.id }
 *     }),
 *   ),
 * )
 *
 * const AppLayer = HttpApiBuilder.layer(MyApi).pipe(
 *   Layer.provide(myGroupLayer),
 *   Layer.provide(layer()),
 *   Layer.provide(myServiceLayer),
 *   Layer.provide(
 *     Layer.mergeAll(
 *       Path.layer,
 *       Etag.layerWeak,
 *       HttpPlatform.layer.pipe(Layer.provide(FileSystem.layerNoop({}))),
 *       FileSystem.layerNoop({}),
 *     ),
 *   ),
 * )
 *
 * const program = Effect.gen(function* () {
 *   const now = new Date()
 *   users.set("u-1", { id: "u-1", name: "Ada", createdAt: now, updatedAt: now, attributes: {} })
 *   const sessionService = yield* SessionService
 *   return (yield* sessionService.createSession("u-1")).token
 * }).pipe(Effect.provide(myServiceLayer))
 *
 * const token = await Effect.runPromise(program)
 * const { handler, dispose } = HttpRouter.toWebHandler(AppLayer)
 * try {
 *   const signedIn = await handler(
 *     new Request("http://localhost/account", { headers: { authorization: `Bearer ${token}` } }),
 *   )
 *   assert.equal(signedIn.status, 200)
 *   assert.deepEqual(await signedIn.json(), { id: "u-1" })
 *   assert.equal((await handler(new Request("http://localhost/account"))).status, 401)
 * } finally {
 *   await dispose()
 * }
 * ```
 *
 * @since 0.1.0
 * @category constructors
 */
export const layer = (config?: CookieConfig): Layer.Layer<AuthMiddleware> => {
  const cfg = resolveCookieConfig(config);

  return Layer.succeed(AuthMiddleware, {
    // `conduit_session` scheme handler: tried first by the security middleware
    // runtime. Reads the request directly so both the cookie AND Bearer/Token
    // header paths are covered, and the signed cookie cache is honoured.
    conduit_session: Effect.fn("AuthMiddleware.conduit_session")(function* (
      ...[handler]: SchemeHandlerArgs<"conduit_session">
    ) {
      const request = yield* HttpServerRequest.HttpServerRequest;
      const maybeResolved = yield* resolveSessionFromRequest(request, cfg).pipe(
        Effect.catchTag("AuthError", requiredAuthFault(request)),
      );
      if (Option.isNone(maybeResolved)) {
        return yield* new S.Unauthorized({ message: "Not authenticated" });
      }
      const { session, user } = maybeResolved.value;
      return yield* handler.pipe(
        Effect.provideService(CurrentSession, session),
        Effect.provideService(CurrentUser, user),
        Effect.provideService(MaybeCurrentSession, maybeResolved),
        Effect.provideService(CurrentPrincipal, principalOf(user)),
        Effect.provideService(CurrentCredential, sessionCredentialClass(session)),
      );
    }),

    // `bearer` scheme handler: fallback tried when `conduit_session` fails.
    // At this point no valid session was found via cookie or bearer in the
    // primary path, so this re-validates the pre-decoded Bearer credential.
    // The credential class is the session's own, whichever header carried
    // its token.
    bearer: Effect.fn("AuthMiddleware.bearer")(function* (
      ...[handler, { credential }]: SchemeHandlerArgs<"bearer">
    ) {
      const token = Redacted.value(credential);
      if (!token) {
        // The session path already met a store fault: answer it, not a 401.
        const request = yield* Effect.serviceOption(HttpServerRequest.HttpServerRequest);
        return yield* Option.isSome(request) && faultedRequests.has(request.value)
          ? new S.InternalServerError({ message: "Internal server error" })
          : new S.Unauthorized({ message: "Not authenticated" });
      }
      const sessionService = yield* SessionService;
      const resolved = yield* sessionService
        .validateSession(token)
        .pipe(
          Effect.catch(sessionValidationFailure),
          Effect.catchTag("AuthError", internalServerError),
        );
      return yield* handler.pipe(
        Effect.provideService(CurrentSession, resolved.session),
        Effect.provideService(CurrentUser, resolved.user),
        Effect.provideService(MaybeCurrentSession, Option.some(resolved)),
        Effect.provideService(CurrentPrincipal, principalOf(resolved.user)),
        Effect.provideService(CurrentCredential, sessionCredentialClass(resolved.session)),
      );
    }),
  });
};

/**
 * Build the `Layer` that implements `OptionalAuthMiddleware`.
 *
 * Reads the session from the request (session cookie or
 * `Authorization: Bearer/Token` header) and validates it via `SessionService`
 * (honoring the signed cookie cache).
 *
 * Provides `MaybeCurrentSession` with `Option.some(resolved)` when
 * authenticated, or `Option.none()` when no session is present or it is
 * invalid. A session or user store fault fails the request with a logged `500`,
 * so an outage never serves signed-in callers as anonymous; pass
 * `onDegraded` to serve them as anonymous instead, reported there.
 *
 * @param config - Optional cookie configuration (name, secure, cache, …).
 *   Defaults match `HttpServer.make` defaults.
 * @param options - `onDegraded`, to degrade a store fault to anonymous.
 *
 * @example
 * ```ts
 * import assert from "node:assert/strict"
 * import { Effect, FileSystem, Layer, Option, Path } from "effect"
 * import * as Schema from "effect/Schema"
 * import { Etag, HttpPlatform, HttpRouter } from "effect/http"
 * import { HttpApi, HttpApiBuilder, HttpApiEndpoint, HttpApiGroup } from "effect/http-api"
 * import { OptionalAuthMiddleware, optionalLayer } from "@thomasfosterau/effect-auth/http"
 * import {
 *   Hooks,
 *   MaybeCurrentSession,
 *   SessionService,
 *   SessionStore,
 *   UserStore,
 *   type Session,
 *   type User,
 * } from "@thomasfosterau/effect-auth"
 *
 * // In-memory stores for the session service. A real app backs these with its database.
 * const sessions = new Map<string, Session>()
 * const users = new Map<string, User>()
 * const storeLayers = Layer.mergeAll(
 *   Layer.succeed(SessionStore, {
 *     create: (session) => Effect.sync(() => (sessions.set(session.id, session), session)),
 *     get: (id) => Effect.sync(() => Option.fromUndefinedOr(sessions.get(id))),
 *     update: (session) =>
 *       Effect.sync(() => (sessions.has(session.id) && sessions.set(session.id, session), session)),
 *     touch: (id, touch) =>
 *       Effect.sync(() => {
 *         const session = sessions.get(id)
 *         if (session === undefined || session.expiresAt < touch.lastActivityAt) return Option.none()
 *         const touched = { ...session, ...touch }
 *         sessions.set(id, touched)
 *         return Option.some(touched)
 *       }),
 *     delete: (id) => Effect.sync(() => void sessions.delete(id)),
 *     deleteByUserId: (userId) =>
 *       Effect.sync(() => {
 *         for (const [id, session] of sessions) if (session.userId === userId) sessions.delete(id)
 *       }),
 *     listByUserId: (userId) =>
 *       Effect.sync(() => [...sessions.values()].filter((s) => s.userId === userId)),
 *   }),
 *   Layer.succeed(UserStore, { get: (id) => Effect.sync(() => Option.fromUndefinedOr(users.get(id))) }),
 * )
 *
 * // Stand-ins for the feed group handlers and the app's services.
 * const myServiceLayer = SessionService.layer({
 *   sessionExpiresIn: { activePeriod: 7 * 86_400_000, idlePeriod: 86_400_000 },
 * }).pipe(Layer.provideMerge(Layer.mergeAll(storeLayers, Hooks.Default)))
 *
 * // The feed is public, but a signed-in viewer sees their own name in it.
 * const FeedSchema = Schema.Struct({ viewer: Schema.NullOr(Schema.String) })
 * const MyApi = HttpApi.make("MyApi").add(
 *   HttpApiGroup.make("feed").add(
 *     HttpApiEndpoint.get("getFeed", "/feed", { success: FeedSchema }).middleware(
 *       OptionalAuthMiddleware,
 *     ),
 *   ),
 * )
 *
 * const myFeedGroupLayer = HttpApiBuilder.group(MyApi, "feed", (handlers) =>
 *   handlers.handle("getFeed", () =>
 *     Effect.gen(function* () {
 *       const viewer = yield* MaybeCurrentSession
 *       return { viewer: Option.isSome(viewer) ? viewer.value.user.id : null }
 *     }),
 *   ),
 * )
 *
 * const AppLayer = HttpApiBuilder.layer(MyApi).pipe(
 *   Layer.provide(myFeedGroupLayer),
 *   Layer.provide(optionalLayer()),
 *   Layer.provide(myServiceLayer),
 *   Layer.provide(
 *     Layer.mergeAll(
 *       Path.layer,
 *       Etag.layerWeak,
 *       HttpPlatform.layer.pipe(Layer.provide(FileSystem.layerNoop({}))),
 *       FileSystem.layerNoop({}),
 *     ),
 *   ),
 * )
 *
 * const program = Effect.gen(function* () {
 *   const now = new Date()
 *   users.set("u-1", { id: "u-1", name: "Ada", createdAt: now, updatedAt: now, attributes: {} })
 *   const sessionService = yield* SessionService
 *   return (yield* sessionService.createSession("u-1")).token
 * }).pipe(Effect.provide(myServiceLayer))
 *
 * const token = await Effect.runPromise(program)
 * const { handler, dispose } = HttpRouter.toWebHandler(AppLayer)
 * try {
 *   const signedIn = await handler(
 *     new Request("http://localhost/feed", { headers: { authorization: `Bearer ${token}` } }),
 *   )
 *   assert.deepEqual(await signedIn.json(), { viewer: "u-1" })
 *
 *   // Anonymous requests are served too, with no viewer.
 *   const anonymous = await handler(new Request("http://localhost/feed"))
 *   assert.equal(anonymous.status, 200)
 *   assert.deepEqual(await anonymous.json(), { viewer: null })
 * } finally {
 *   await dispose()
 * }
 * ```
 *
 * @since 0.1.0
 * @category constructors
 */
export const optionalLayer = (
  config?: CookieConfig,
  options?: OptionalAuthOptions,
): Layer.Layer<OptionalAuthMiddleware> => {
  const cfg = resolveCookieConfig(config);
  const onDegraded = options?.onDegraded;

  return Layer.succeed(
    OptionalAuthMiddleware,
    Effect.fn("OptionalAuthMiddleware")(function* (handler, _opts) {
      const request = yield* HttpServerRequest.HttpServerRequest;
      // An absent or refused session is anonymous; a store fault is a 500
      // unless the app asked to degrade it.
      const maybeResolved = yield* resolveSessionFromRequest(request, cfg).pipe(
        Effect.catchTags({
          Unauthorized: () => Effect.succeed(Option.none<Types.SessionWithUser>()),
          AuthError: (error) =>
            onDegraded === undefined
              ? internalServerError(error)
              : onDegraded(Cause.fail(error)).pipe(Effect.as(Option.none<Types.SessionWithUser>())),
        }),
      );
      // `CurrentPrincipal`/`CurrentCredential` only exist when someone is
      // actually authenticated, so they are added to the context but never
      // subtracted from the handler's requirements (see
      // `OptionalAuthMiddleware`).
      const withPrincipal = <A, E, R>(effect: Effect.Effect<A, E, R>): Effect.Effect<A, E, R> =>
        Option.isNone(maybeResolved)
          ? effect
          : Effect.provideService(
              Effect.provideService(
                effect,
                CurrentPrincipal,
                principalOf(maybeResolved.value.user),
              ),
              CurrentCredential,
              sessionCredentialClass(maybeResolved.value.session),
            );

      return yield* withPrincipal(
        handler.pipe(Effect.provideService(MaybeCurrentSession, maybeResolved)),
      );
    }),
  );
};
