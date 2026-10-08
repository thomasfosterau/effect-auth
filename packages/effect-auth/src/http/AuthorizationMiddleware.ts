/**
 * Route-level policy gate: a `HttpApiMiddleware` that runs the `Authorizer`
 * against a per-route `AuthorizeInput` and turns a deny into the wire-level
 * 403 `Forbidden` error.
 *
 * `AuthMiddleware` (`./HttpMiddleware.ts`) answers *who* is calling by
 * providing `CurrentPrincipal`; this module answers *may they do this* by
 * reading that principal, asking `Authorizer.authorize`, and gating the
 * handler on the answer. The two compose: attach `AuthMiddleware` (or
 * otherwise put `CurrentPrincipal` in context) first, then a middleware from
 * {@link makeAuthorizationMiddleware} for each route whose resource needs a policy
 * check.
 *
 * ## Why a factory, not a single exported tag
 *
 * `AuthMiddleware` is one static `HttpApiMiddleware.Service` because every
 * route needs the exact same thing from it (a validated session). Authorization
 * is different: almost every route protects a *different* resource — `doc-1`
 * on one endpoint, `org-42` on the next — so `AuthorizeInput` is inherently
 * per-route, not a single static value. {@link makeAuthorizationMiddleware} therefore
 * builds a fresh `HttpApiMiddleware.Service` class (with its own unique tag
 * id and its own baked-in `Layer`) on every call, so each route attaches its
 * own instance carrying its own resource/action.
 *
 * Each guard is named by its first argument, and that name is its TypeScript
 * type: attaching one guard and providing another guard's `.layer` is a compile
 * error, not a missing-service failure at runtime (#320).
 *
 * ## Static vs. per-request input
 *
 * Most resources are per-request (a path param, a value read from
 * `HttpServerRequest`, sometimes both), so `makeAuthorizationMiddleware` accepts
 * either:
 *
 * - a fixed {@link AuthorizeInput} — the resource is the same for every call
 *   to this route (rare, but valid: e.g. a `system:admin-panel` singleton
 *   resource);
 * - a `(request) => AuthorizeInput` function — the common case;
 * - a `(request) => Effect<AuthorizeInput>` function — when deriving the
 *   input needs more than the raw request. The function runs inside the same
 *   context the downstream handler would, so it may itself `yield*` ambient
 *   framework services to shape the resource, e.g.
 *   `HttpRouter.RouteContext` for path params (`GET /docs/:id` → the `id`
 *   segment) or `HttpServerRequest.ParsedSearchParams` for query params.
 *   Errors are intentionally not supported here (`R`'s error channel is
 *   `never`) — resolve or default inside the function; a route whose
 *   resource genuinely cannot be determined should fail some other way
 *   before authorization is even relevant.
 *
 * `HttpApiMiddleware`'s `options` argument only carries the *static*
 * endpoint/group metadata, not decoded path params — but path params are not
 * out of reach: `RouteContext` (and therefore path params) is part of
 * `HttpRouter.Provided`, ambiently available to every `HttpApiMiddleware`
 * alongside `HttpServerRequest` (see `@effect-expect-leaking` below, mirroring
 * `AuthMiddleware`'s own note on this). So the middleware-function shape
 * *does* express per-route, per-request resources cleanly; no handler-level
 * fallback combinator was needed.
 *
 * ## Denial handling
 *
 * On deny, the client sees `Forbidden` (403) with a message naming the
 * {@link Policy.Decision.reason} (`"forbid"` or `"default-deny"`) — enough to
 * distinguish "a policy explicitly forbids this" from "no policy allows it"
 * without leaking policy ids or the full evaluation trace. The full
 * `Decision` (`determining`/`outcomes`) is logged via `Effect.logDebug` for
 * operators, never returned to the caller. Any other failure surfaced while
 * computing the decision (e.g. an `EntityResolver` failure) is treated the
 * same way the `Authorizer`/`Protected` field guard already treats such
 * failures — fail-closed, as `Forbidden` — and logged via `Effect.logError`.
 *
 * @example Gate one endpoint on a per-request resource
 * ```ts
 * import { Effect } from "effect"
 * import { HttpRouter } from "effect/http"
 * import { HttpApiEndpoint, HttpApiGroup } from "effect/http-api"
 * import { Entity } from "@thomasfosterau/effect-auth"
 * import { AuthMiddleware, makeAuthorizationMiddleware } from "@thomasfosterau/effect-auth/http"
 *
 * // A route-level gate: AuthMiddleware answers "who is calling", this answers
 * // "may they do this". The name gives this guard its own type. The resource
 * // comes from the request's `:docId` path param; pass a plain
 * // `{ action, resource }` instead when it is fixed.
 * const RequireDocRead = makeAuthorizationMiddleware("RequireDocRead", (_request) =>
 *   Effect.gen(function* () {
 *     const params = yield* HttpRouter.params
 *     return { action: "doc:read", resource: Entity.ref("Document", params["docId"]!) }
 *   }),
 * )
 *
 * // Attach it after AuthMiddleware so the principal is resolved first.
 * const DocsGroup = HttpApiGroup.make("docs").add(
 *   HttpApiEndpoint.get("getDoc", "/docs/:docId", {})
 *     .middleware(AuthMiddleware)
 *     .middleware(RequireDocRead),
 * )
 * ```
 *
 * @module http/authorization-middleware
 */

import { Context, Effect, Layer } from "effect";
import { HttpApiMiddleware } from "effect/http-api";
import { HttpRouter, HttpServerRequest } from "effect/http";
import { Authorizer, CurrentPrincipal, type AuthorizeInput } from "../Authorizer.ts";
import * as S from "./HttpApiSchema.ts";

// =============================================================================
// Input shapes
// =============================================================================

/**
 * Derives the per-request {@link AuthorizeInput} from the incoming request.
 * Runs inside the middleware's own context — the same ambient framework
 * services (`HttpServerRequest`, `HttpRouter.RouteContext`,
 * `HttpServerRequest.ParsedSearchParams`) available to any `HttpApiMiddleware`
 * are reachable from inside the returned `Effect` — so it can name a resource
 * built from a path param, a query param, or the raw request alike.
 *
 * The error channel is intentionally `never`: this is meant to *shape* an
 * `AuthorizeInput`, not to run business logic that can fail. A route whose
 * resource cannot be determined should fail before reaching authorization.
 *
 * @since 1.0.0
 * @category models
 */
export type DynamicAuthorizeInput<R = never> = (
  request: HttpServerRequest.HttpServerRequest,
) => AuthorizeInput | Effect.Effect<AuthorizeInput, never, R>;

/**
 * What {@link makeAuthorizationMiddleware} accepts: a fixed {@link AuthorizeInput} for
 * routes whose resource never varies, or a {@link DynamicAuthorizeInput} for
 * the common per-request case.
 *
 * @since 1.0.0
 * @category models
 */
export type AuthorizationMiddlewareInput<R = never> = AuthorizeInput | DynamicAuthorizeInput<R>;

// Every call to `makeAuthorizationMiddleware` needs its own tag id: `Context` treats
// two `Context.Service` classes constructed with the same string id as the
// same key, and a real app attaches a different instance (a different
// resource) to nearly every route. A shared id would make the second
// `.middleware(...)`/`.layer` silently collide with the first.
let _nextMiddlewareId = 0;

const resolveAuthorizeInput = <R>(
  input: AuthorizationMiddlewareInput<R>,
  request: HttpServerRequest.HttpServerRequest,
): Effect.Effect<AuthorizeInput, never, R> => {
  if (typeof input !== "function") return Effect.succeed(input);
  const result = input(request);
  return Effect.isEffect(result) ? result : Effect.succeed(result);
};

/**
 * What a guard requires from context: `Authorizer` and `CurrentPrincipal`, plus
 * the factory's `R`. `HttpRouter.Provided` (the request, its scope, its
 * search params and its route context) is left out, because the router supplies
 * it to every middleware on each request. Leaving it in would make an endpoint
 * that reads a path param require `RouteContext` from its layer, which no layer
 * can provide.
 *
 * @since 1.0.0
 * @category models
 */
export type AuthorizationRequires<R = never> =
  | Authorizer
  | CurrentPrincipal
  | Exclude<R, HttpRouter.Provided>;

/**
 * The static `HttpApiMiddleware` configuration every
 * {@link makeAuthorizationMiddleware} instance shares: it requires
 * `Authorizer | CurrentPrincipal | R`, provides nothing, and fails with
 * `Forbidden` (403).
 *
 * @since 1.0.0
 * @category models
 */
export type AuthorizationMiddlewareConfig<R = never> = {
  requires: AuthorizationRequires<R>;
  provides: never;
  error: typeof S.ForbiddenError;
  clientError: never;
  requiredForClient: false;
  security: never;
};

/**
 * The identifier of a middleware built by {@link makeAuthorizationMiddleware}:
 * the instance type that `HttpApiEndpoint.middleware(...)` and
 * `HttpApiGroup.middleware(...)` accept, and that `Layer`s and `Context` key on.
 *
 * It is the instance type of an `HttpApiMiddleware.ServiceClass`, the same
 * shape a class-declared middleware such as `AuthMiddleware` has. The
 * `HttpApiMiddleware` machinery reads the requirements and error schema off
 * that instance, so an identifier typed as the class value (rather than its
 * instance) is rejected with a type error at `.middleware(...)`.
 *
 * `Id` is the guard's name, carried as the instance's `key` literal. It is what
 * makes two guards with the same `R` different types.
 *
 * @since 1.0.0
 * @category models
 */
export type AuthorizationMiddlewareInstance<
  R = never,
  Id extends string = string,
> = Context.ServiceClass.Shape<
  Id,
  HttpApiMiddleware.HttpApiMiddleware<never, typeof S.ForbiddenError, AuthorizationRequires<R>>
> & {
  readonly "~effect/http-api/HttpApiMiddleware": {
    readonly error: typeof S.ForbiddenError;
    readonly requires: AuthorizationRequires<R>;
    readonly provides: never;
    readonly clientError: never;
    readonly requiredForClient: false;
  };
};

/**
 * The class type {@link makeAuthorizationMiddleware} returns: an
 * `HttpApiMiddleware.ServiceClass` requiring `Authorizer | CurrentPrincipal | R`
 * with its implementing {@link AuthorizationMiddlewareClass.layer | layer} attached.
 *
 * `Id` is the name the guard was built with. Each name is its own type, so
 * `.middleware(...)` and `.layer` pair up one-to-one with the guard that was
 * built: providing another guard's `.layer` fails to type-check. The runtime
 * tag is unique per factory call regardless of name.
 *
 * @since 1.0.0
 * @category models
 */
export interface AuthorizationMiddlewareClass<
  R = never,
  Id extends string = string,
> extends HttpApiMiddleware.ServiceClass<
  AuthorizationMiddlewareInstance<R, Id>,
  Id,
  AuthorizationMiddlewareConfig<R>
> {
  /**
   * The `Layer` implementing this middleware instance. Provide it alongside
   * the application layer, next to wherever `AuthMiddleware`'s `layer()` and
   * `Authorizer.layer(...)` are provided.
   */
  readonly layer: Layer.Layer<AuthorizationMiddlewareInstance<R, Id>>;
}

// =============================================================================
// makeAuthorizationMiddleware
// =============================================================================

/**
 * Build a route-level `HttpApiMiddleware` that gates the handler on
 * `Authorizer.authorize(input)` for the {@link CurrentPrincipal} already in
 * context.
 *
 * Attach the returned class with `.middleware(...)` to whichever
 * `HttpApiEndpoint`/`HttpApiGroup` the policy protects, and provide its
 * `.layer` alongside the application layer — mirroring how `AuthMiddleware`
 * and its `layer()` are attached (see the module doc's example).
 *
 * **Naming.** `name` is the guard's type identity, so give each guard its own
 * name. Two guards built with the same name share a type again, and a wrong
 * `.layer` between them type-checks and then fails at runtime. The name also
 * labels the runtime tag, but the tag is unique per call either way.
 *
 * **Composition order.** `CurrentPrincipal` is declared in `requires`, so a
 * consumer who forgets to also attach `AuthMiddleware` (or otherwise put
 * `CurrentPrincipal` in context — e.g. a service-to-service principal) gets a
 * compile error: the final `HttpApiBuilder.layer(...)` composition will still
 * demand `CurrentPrincipal` in its context requirements. That check is
 * necessary but not sufficient — it catches a *missing* provider, not a
 * *wrongly ordered* one. At runtime `CurrentPrincipal` must actually be
 * resolved by the time this middleware's handler runs, which means
 * `AuthMiddleware` must be the one wrapping this middleware (applied so its
 * `Effect.provideService(CurrentPrincipal, ...)` is in effect before this
 * middleware's body executes) — not the other way around. Order it after
 * `AuthMiddleware` in the endpoint's `.middleware()` chain.
 *
 * On allow, the handler runs unchanged — no new services are provided
 * (`provides` is empty; the `Decision` is not exposed downstream, matching
 * `Authorizer.check`'s posture that a route only needs the boolean/gate, not
 * the trace).
 *
 * On deny (`AuthorizationDeniedError`) or any other failure while deciding
 * (`Errors.AuthError`, fail-closed), fails with `Forbidden` (403). The
 * message names the {@link Policy.Decision.reason}; the full trace is logged
 * (`Effect.logDebug` for a normal deny, `Effect.logError` for an
 * infrastructure failure) rather than sent to the client.
 *
 * @effect-expect-leaking HttpServerRequest
 * @effect-expect-leaking ParsedSearchParams
 * @effect-expect-leaking RouteContext
 *
 * @since 1.0.0
 * @category constructors
 */
export const makeAuthorizationMiddleware = <const Id extends string, R = never>(
  name: Id,
  input: AuthorizationMiddlewareInput<R>,
): AuthorizationMiddlewareClass<R, Id> => {
  const id = `@effect-auth/AuthorizationMiddleware/${name}#${_nextMiddlewareId++}`;

  class AuthorizationMiddleware extends HttpApiMiddleware.Service<
    AuthorizationMiddleware,
    { requires: AuthorizationRequires<R> }
  >()(id, { error: S.ForbiddenError }) {
    /**
     * The `Layer` implementing this middleware instance. Provide it
     * alongside the application layer, next to wherever `AuthMiddleware`'s
     * `layer()` and `Authorizer.layer(...)` are provided.
     */
    static readonly layer: Layer.Layer<AuthorizationMiddleware> = Layer.succeed(
      AuthorizationMiddleware,
      (handler, _opts) =>
        Effect.gen(function* () {
          const authorizer = yield* Authorizer;
          const request = yield* HttpServerRequest.HttpServerRequest;
          // `R` may name a service the router provides per request (see
          // `AuthorizationRequires`). Widening the requirement back to
          // `AuthorizationRequires<R>` is sound: `R` is covered by that union
          // plus the router's `Provided`, and TypeScript can't split a generic `R`.
          const authInput = yield* resolveAuthorizeInput(input, request) as Effect.Effect<
            AuthorizeInput,
            never,
            AuthorizationRequires<R>
          >;

          yield* authorizer.authorize(authInput).pipe(
            Effect.catchTags({
              AuthorizationDeniedError: (e) =>
                Effect.logDebug("effect-auth: authorization denied", {
                  reason: e.decision.reason,
                  decision: e.decision,
                }).pipe(
                  Effect.andThen(
                    Effect.fail(
                      new S.Forbidden({
                        message: `Not authorized: ${e.decision.reason}`,
                        code: e.decision.reason,
                      }),
                    ),
                  ),
                ),
              AuthError: (e) =>
                Effect.logError("effect-auth: authorization check failed", e).pipe(
                  Effect.andThen(
                    Effect.fail(
                      new S.Forbidden({ message: "Not authorized: authorization check failed" }),
                    ),
                  ),
                ),
            }),
          );

          return yield* handler;
        }),
    );
  }

  // The local class's Self brand can never equal the shared interface's —
  // the cast erases only that brand. Runtime identity lives in the unique
  // tag id, which the cast does not touch; the type identity is `Id`.
  return AuthorizationMiddleware as unknown as AuthorizationMiddlewareClass<R, Id>;
};
