/**
 * Composable `HttpApiMiddleware` for effect-auth.
 *
 * Provides drop-in auth guards for any consumer `HttpApi` application:
 *
 * - `CurrentSession` / `CurrentUser` — context services injected by the
 *   required-auth middleware so downstream handlers can `yield* CurrentUser`
 *   without knowing how the session was resolved.
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
 * import { HttpApiGroup, HttpApiEndpoint, HttpApiBuilder } from "effect/unstable/httpapi"
 * import { Effect, Layer } from "effect"
 * import {
 *   AuthMiddleware,
 *   CurrentUser,
 *   layer,
 * } from "@thomasfosterau/effect-auth/Http"
 *
 * // 1. Define API group – mark endpoints that need auth
 * const ProfileGroup = HttpApiGroup.make("profile").pipe(
 *   HttpApiGroup.add(
 *     HttpApiEndpoint.get("getProfile", "/profile").pipe(
 *       HttpApiEndpoint.setSuccess(ProfileSchema),
 *       HttpApiEndpoint.middleware(AuthMiddleware),
 *     )
 *   )
 * )
 *
 * // 2. Implement the handler – CurrentUser is available in context
 * const ProfileGroupLayer = HttpApiBuilder.group(MyApi, "profile", (handlers) =>
 *   handlers.handle("getProfile", () =>
 *     Effect.gen(function* () {
 *       const user = yield* CurrentUser
 *       return { id: user.id, email: user.email }
 *     })
 *   )
 * )
 *
 * // 3. Wire up the middleware layer alongside your service layer
 * const AppLayer = HttpApiBuilder.layer(MyApi).pipe(
 *   Layer.provide(ProfileGroupLayer),
 *   Layer.provide(layer()),
 *   Layer.provide(myServiceLayer), // must provide SessionService, Hooks, …
 * )
 * ```
 */

import { Context, Effect, Layer, Option, Redacted } from "effect";
import { HttpApiMiddleware, HttpApiSecurity } from "effect/unstable/httpapi";
import { HttpServerRequest } from "effect/unstable/http";
import { Hooks } from "../Hooks.ts";
import { SessionService } from "../session/SessionService.ts";
import { resolveMessage } from "../Messages.ts";
import * as S from "./HTTPApiSchemas.ts";
import type * as Types from "../Types.ts";
import {
  dataCookieName,
  resolveCookieConfig,
  sessionIdFromRequest,
  type CookieConfig,
  type ResolvedCookieConfig,
} from "./HTTPServer.ts";
import { decodeSessionCacheCookie } from "../SessionCookieCache.ts";

// =============================================================================
// Context services
// =============================================================================

/**
 * Context service that holds the validated `Session` for the current request.
 *
 * Available in handlers that have `AuthMiddleware` applied. Use
 * `MaybeCurrentSession` when auth is optional.
 *
 * @since 1.0.0
 * @category context
 */
export class CurrentSession extends Context.Service<CurrentSession, Types.Session>()(
  "@effect-auth/CurrentSession",
) {}

/**
 * Context service that holds the authenticated `User` for the current request.
 *
 * Available in handlers that have `AuthMiddleware` applied. Use
 * `MaybeCurrentSession` when auth is optional.
 *
 * @since 1.0.0
 * @category context
 */
export class CurrentUser extends Context.Service<CurrentUser, Types.User>()(
  "@effect-auth/CurrentUser",
) {}

/**
 * Context service that holds an `Option<SessionWithUser>` for optional-auth
 * handlers.
 *
 * Available in handlers that have `OptionalAuthMiddleware` applied.
 * `Option.some(resolved)` when a valid session is present; `Option.none()`
 * when unauthenticated or session is invalid.
 *
 * @since 1.0.0
 * @category context
 */
export class MaybeCurrentSession extends Context.Service<
  MaybeCurrentSession,
  Option.Option<Types.SessionWithUser>
>()("@effect-auth/MaybeCurrentSession") {}

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
 * (honoring the signed cookie cache), and provides `CurrentSession` and
 * `CurrentUser` to the downstream handler.
 *
 * Fails with `Unauthorized` (HTTP 401) when the session is absent, expired, or
 * invalid.
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
  { requires: SessionService | Hooks; provides: CurrentSession | CurrentUser }
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
          const resolved = decodeSessionCacheCookie(cached, cfg.cache, Date.now(), primaryId);
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
 *   Defaults match `HTTPServer.make` defaults (`name: "conduit_session"`,
 *   `secure: true`).
 *
 * @example
 * ```ts
 * const AppLayer = HttpApiBuilder.layer(MyApi).pipe(
 *   Layer.provide(myGroupLayer),
 *   Layer.provide(layer()),
 *   Layer.provide(myServiceLayer),
 * )
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
    conduit_session: (handler, _opts) =>
      Effect.gen(function* () {
        const request = yield* HttpServerRequest.HttpServerRequest;
        const maybeResolved = yield* resolveSessionFromRequest(request, cfg);
        if (Option.isNone(maybeResolved)) {
          return yield* new S.Unauthorized({ message: "Not authenticated" });
        }
        const { session, user } = maybeResolved.value;
        return yield* handler.pipe(
          Effect.provideService(CurrentSession, session),
          Effect.provideService(CurrentUser, user),
        );
      }),

    // `bearer` scheme handler: fallback tried when `conduit_session` fails.
    // At this point no valid session was found via cookie or bearer in the
    // primary path, so this re-validates the pre-decoded Bearer credential.
    bearer: (handler, { credential }) =>
      Effect.gen(function* () {
        const token = Redacted.value(credential);
        if (!token) {
          return yield* new S.Unauthorized({ message: "Not authenticated" });
        }
        const resolved = yield* validateToken(token);
        return yield* handler.pipe(
          Effect.provideService(CurrentSession, resolved.session),
          Effect.provideService(CurrentUser, resolved.user),
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
 *   Defaults match `HTTPServer.make` defaults.
 *
 * @example
 * ```ts
 * const AppLayer = HttpApiBuilder.layer(MyApi).pipe(
 *   Layer.provide(myFeedGroupLayer),
 *   Layer.provide(optionalLayer()),
 *   Layer.provide(myServiceLayer),
 * )
 * ```
 *
 * @since 1.0.0
 * @category constructors
 */
export const optionalLayer = (config?: CookieConfig): Layer.Layer<OptionalAuthMiddleware> => {
  const cfg = resolveCookieConfig(config);

  return Layer.succeed(OptionalAuthMiddleware, (handler, _opts) =>
    Effect.gen(function* () {
      const request = yield* HttpServerRequest.HttpServerRequest;
      const maybeResolved = yield* resolveSessionFromRequest(request, cfg).pipe(
        Effect.catch(() => Effect.succeed(Option.none<Types.SessionWithUser>())),
      );
      return yield* handler.pipe(Effect.provideService(MaybeCurrentSession, maybeResolved));
    }),
  );
};
