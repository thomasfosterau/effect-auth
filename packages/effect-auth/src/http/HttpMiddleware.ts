/**
 * Composable `HttpApiMiddleware` for effect-auth.
 *
 * Provides drop-in auth guards for any consumer `HttpApi` application:
 *
 * - `CurrentSession` / `CurrentUser` — context services injected by the
 *   required-auth middleware so downstream handlers can `yield* CurrentUser`
 *   without knowing how the session was resolved.
 * - `CurrentPrincipal` / `CurrentCredential` — the resolved principal
 *   (`Authorizer.ts`) and how it was authenticated: `"interactive"` for the
 *   session cookie, `"machine"` for the `Authorization` header. Read by
 *   `Authorizer.authorize`/`check` so a policy can gate an operation on
 *   credential class, not just identity.
 * - `MaybeCurrentSession` — analogous service for optional-auth handlers;
 *   holds `Option<SessionWithUser>` (some when authenticated, none otherwise).
 * - `AuthMiddleware` — required-auth `HttpApiMiddleware.Service` tag.
 * - `OptionalAuthMiddleware` — optional-auth variant; never fails.
 * - `layer(config?)` — returns the `Layer` that implements
 *   `AuthMiddleware`. Reads the session cookie (honoring the cache) or an
 *   `Authorization: Bearer/Token` header; fails with `Unauthorized` (401) when
 *   neither is present or the session is expired/invalid.
 * - `optionalLayer(config?)` — returns the `Layer` that
 *   implements `OptionalAuthMiddleware`. Never fails; provides
 *   `MaybeCurrentSession` with `Option.none()` when unauthenticated.
 *
 * The `AuthMiddleware` class carries `HttpApiSecurity` definitions for the
 * session cookie and Bearer token schemes so the derived OpenAPI spec
 * advertises both supported auth methods.
 *
 * @example Attaching required auth to a group
 * ```ts
 * import assert from "node:assert/strict"
 * import { Effect, FileSystem, Layer, Path, Schema } from "effect"
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
 *     get: (id) => Effect.sync(() => sessions.get(id) ?? null),
 *     update: (session) => Effect.sync(() => (sessions.set(session.id, session), session)),
 *     delete: (id) => Effect.sync(() => void sessions.delete(id)),
 *     deleteByUserId: (userId) =>
 *       Effect.sync(() => {
 *         for (const [id, session] of sessions) if (session.userId === userId) sessions.delete(id)
 *       }),
 *     listByUserId: (userId) =>
 *       Effect.sync(() => [...sessions.values()].filter((s) => s.userId === userId)),
 *   }),
 *   Layer.succeed(UserStore, { get: (id) => Effect.sync(() => users.get(id) ?? null) }),
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
 *   return (yield* sessionService.createSession("u-1")).id
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

import { Effect, Layer, Option, Redacted } from "effect";
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
import { resolveMessage } from "../Messages.ts";
import * as S from "./HttpApiSchema.ts";
import type * as Types from "../Types.ts";
import {
  dataCookieName,
  resolveCookieConfig,
  sessionIdFromRequest,
  credentialClassFromRequest,
  type CookieConfig,
  type ResolvedCookieConfig,
} from "./HttpServer.ts";
import { decodeSessionCacheCookie, sessionCacheGateAttributes } from "../SessionCookieCache.ts";

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
 * @since 1.0.0
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
 * @since 1.0.0
 * @category security
 */
export const sessionCookieSecurity: HttpApiSecurity.ApiKey = HttpApiSecurity.apiKey({
  key: "conduit_session",
  in: "cookie",
});

/**
 * `HttpApiSecurity` describing the `Authorization: Bearer` scheme.
 *
 * @since 1.0.0
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
 * `CurrentCredential` (`"interactive"` for the session cookie, `"machine"`
 * for the `Authorization` header) to the downstream handler.
 *
 * Fails with `Unauthorized` (HTTP 401) when the session is absent, expired, or
 * invalid.
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
 * @since 1.0.0
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
  error: S.UnauthorizedError,
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
 * never fails: when no valid session is found, it provides
 * `MaybeCurrentSession` with `Option.none()`.
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
 * @since 1.0.0
 * @category middleware
 */
export class OptionalAuthMiddleware extends HttpApiMiddleware.Service<
  OptionalAuthMiddleware,
  { requires: SessionService | Hooks; provides: MaybeCurrentSession }
>()("@effect-auth/OptionalAuthMiddleware") {}

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
 * Fails with `Unauthorized` when a token is present but invalid/expired.
 */
const resolveSessionFromRequest = (
  request: HttpServerRequest.HttpServerRequest,
  cfg: ResolvedCookieConfig,
): Effect.Effect<Option.Option<Types.SessionWithUser>, S.Unauthorized, SessionService | Hooks> =>
  Effect.gen(function* () {
    // --- Cache path ---
    if (cfg.cache !== undefined) {
      const primaryId = sessionIdFromRequest(request, cfg);
      if (primaryId !== undefined) {
        const cached = request.cookies[dataCookieName(cfg)];
        if (cached !== undefined) {
          const gate = yield* sessionCacheGateAttributes;
          const resolved = decodeSessionCacheCookie(cached, cfg.cache, Date.now(), primaryId, gate);
          if (resolved !== null) return Option.some(resolved);
        }
      }
    }

    // --- Store path ---
    const sessionId = sessionIdFromRequest(request, cfg);
    if (sessionId === undefined) return Option.none<Types.SessionWithUser>();

    const sessionService = yield* SessionService;
    const resolved = yield* sessionService.validateSession(sessionId).pipe(
      Effect.catchTag("UserBannedError", (e) =>
        resolveMessage(e.code, e.message).pipe(
          Effect.flatMap((msg) => Effect.fail(new S.Unauthorized({ message: msg, code: e.code }))),
        ),
      ),
      Effect.mapError(() => new S.Unauthorized({ message: "Invalid or expired session" })),
    );

    return Option.some(resolved);
  });

// Internal helper to validate a raw token directly (used by bearer fallback).
const validateToken = (
  token: string,
): Effect.Effect<Types.SessionWithUser, S.Unauthorized, SessionService | Hooks> =>
  Effect.gen(function* () {
    const sessionService = yield* SessionService;
    return yield* sessionService.validateSession(token).pipe(
      Effect.catchTag("UserBannedError", (e) =>
        resolveMessage(e.code, e.message).pipe(
          Effect.flatMap((msg) => Effect.fail(new S.Unauthorized({ message: msg, code: e.code }))),
        ),
      ),
      Effect.mapError(() => new S.Unauthorized({ message: "Invalid or expired session" })),
    );
  });

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
 * invalid.
 *
 * @param config - Optional cookie configuration (name, secure, cache, …).
 *   Defaults match `HttpServer.make` defaults (`name: "conduit_session"`,
 *   `secure: true`).
 *
 * @example
 * ```ts
 * import assert from "node:assert/strict"
 * import { Effect, FileSystem, Layer, Path, Schema } from "effect"
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
 *     get: (id) => Effect.sync(() => sessions.get(id) ?? null),
 *     update: (session) => Effect.sync(() => (sessions.set(session.id, session), session)),
 *     delete: (id) => Effect.sync(() => void sessions.delete(id)),
 *     deleteByUserId: (userId) =>
 *       Effect.sync(() => {
 *         for (const [id, session] of sessions) if (session.userId === userId) sessions.delete(id)
 *       }),
 *     listByUserId: (userId) =>
 *       Effect.sync(() => [...sessions.values()].filter((s) => s.userId === userId)),
 *   }),
 *   Layer.succeed(UserStore, { get: (id) => Effect.sync(() => users.get(id) ?? null) }),
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
 *   return (yield* sessionService.createSession("u-1")).id
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
 * @since 1.0.0
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
      const maybeResolved = yield* resolveSessionFromRequest(request, cfg);
      if (Option.isNone(maybeResolved)) {
        return yield* new S.Unauthorized({ message: "Not authenticated" });
      }
      const { session, user } = maybeResolved.value;
      return yield* handler.pipe(
        Effect.provideService(CurrentSession, session),
        Effect.provideService(CurrentUser, user),
        Effect.provideService(MaybeCurrentSession, maybeResolved),
        Effect.provideService(CurrentPrincipal, principalOf(user)),
        Effect.provideService(CurrentCredential, credentialClassFromRequest(request)),
      );
    }),

    // `bearer` scheme handler: fallback tried when `conduit_session` fails.
    // At this point no valid session was found via cookie or bearer in the
    // primary path, so this re-validates the pre-decoded Bearer credential.
    // Reached only via the `Authorization` header, so the credential is
    // unconditionally "machine".
    bearer: Effect.fn("AuthMiddleware.bearer")(function* (
      ...[handler, { credential }]: SchemeHandlerArgs<"bearer">
    ) {
      const token = Redacted.value(credential);
      if (!token) {
        return yield* new S.Unauthorized({ message: "Not authenticated" });
      }
      const resolved = yield* validateToken(token);
      return yield* handler.pipe(
        Effect.provideService(CurrentSession, resolved.session),
        Effect.provideService(CurrentUser, resolved.user),
        Effect.provideService(MaybeCurrentSession, Option.some(resolved)),
        Effect.provideService(CurrentPrincipal, principalOf(resolved.user)),
        Effect.provideService(CurrentCredential, "machine"),
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
 * Always succeeds: provides `MaybeCurrentSession` with
 * `Option.some(resolved)` when authenticated, or `Option.none()` when no
 * session is present or it is invalid.
 *
 * @param config - Optional cookie configuration (name, secure, cache, …).
 *   Defaults match `HttpServer.make` defaults.
 *
 * @example
 * ```ts
 * import assert from "node:assert/strict"
 * import { Effect, FileSystem, Layer, Option, Path, Schema } from "effect"
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
 *     get: (id) => Effect.sync(() => sessions.get(id) ?? null),
 *     update: (session) => Effect.sync(() => (sessions.set(session.id, session), session)),
 *     delete: (id) => Effect.sync(() => void sessions.delete(id)),
 *     deleteByUserId: (userId) =>
 *       Effect.sync(() => {
 *         for (const [id, session] of sessions) if (session.userId === userId) sessions.delete(id)
 *       }),
 *     listByUserId: (userId) =>
 *       Effect.sync(() => [...sessions.values()].filter((s) => s.userId === userId)),
 *   }),
 *   Layer.succeed(UserStore, { get: (id) => Effect.sync(() => users.get(id) ?? null) }),
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
 *   return (yield* sessionService.createSession("u-1")).id
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
 * @since 1.0.0
 * @category constructors
 */
export const optionalLayer = (config?: CookieConfig): Layer.Layer<OptionalAuthMiddleware> => {
  const cfg = resolveCookieConfig(config);

  return Layer.succeed(
    OptionalAuthMiddleware,
    Effect.fn("OptionalAuthMiddleware")(function* (handler, _opts) {
      const request = yield* HttpServerRequest.HttpServerRequest;
      const maybeResolved = yield* resolveSessionFromRequest(request, cfg).pipe(
        Effect.catch(() => Effect.succeed(Option.none<Types.SessionWithUser>())),
      );
      // `CurrentPrincipal`/`CurrentCredential` only exist when someone is
      // actually authenticated, so they are added to the context but never
      // subtracted from the handler's requirements (see
      // `OptionalAuthMiddleware`).
      // SAFETY: re-widening `R` after `provideService` is sound: providing a
      // service only ever removes one.
      const withPrincipal = <A, E, R>(effect: Effect.Effect<A, E, R>): Effect.Effect<A, E, R> =>
        Option.isNone(maybeResolved)
          ? effect
          : (Effect.provideService(
              Effect.provideService(
                effect,
                CurrentPrincipal,
                principalOf(maybeResolved.value.user),
              ),
              CurrentCredential,
              credentialClassFromRequest(request),
            ) as Effect.Effect<A, E, R>);

      return yield* withPrincipal(
        handler.pipe(Effect.provideService(MaybeCurrentSession, maybeResolved)),
      );
    }),
  );
};
