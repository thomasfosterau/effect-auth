/**
 * Route-level policy gate: {@link makeAuthorizationMiddleware} runs the
 * `Authorizer` on a per-route input, fixed or derived from the request, and
 * answers a deny, or a failure to decide, with a `403` naming only the reason.
 * The full trace is logged, never returned.
 *
 * @example Gate one endpoint on a per-request resource
 * ```ts
 * import assert from "node:assert/strict"
 * import { Effect, FileSystem, Layer, Option, Path } from "effect"
 * import { Etag, HttpPlatform, HttpRouter } from "effect/http"
 * import { HttpApi, HttpApiBuilder, HttpApiEndpoint, HttpApiGroup } from "effect/http-api"
 * import { AuthMiddleware, layer as authLayer, makeAuthorizationMiddleware } from "@thomasfosterau/effect-auth/http"
 * import {
 *   Authorizer,
 *   Condition,
 *   Entity,
 *   EntityResolver,
 *   Hooks,
 *   memoryEntityResolver,
 *   Policy,
 *   SessionService,
 *   SessionStore,
 *   UserStore,
 *   type Session,
 *   type User,
 * } from "@thomasfosterau/effect-auth"
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
 * // Attach it before AuthMiddleware: later `.middleware(...)` calls run first, so
 * // AuthMiddleware resolves the principal before the gate reads it.
 * const DocsApi = HttpApi.make("DocsApi").add(
 *   HttpApiGroup.make("docs").add(
 *     HttpApiEndpoint.get("getDoc", "/docs/:docId", {})
 *       .middleware(RequireDocRead)
 *       .middleware(AuthMiddleware),
 *   ),
 * )
 *
 * const docsGroup = HttpApiBuilder.group(DocsApi, "docs", (handlers) =>
 *   handlers.handle("getDoc", () => Effect.void),
 * )
 *
 * // Policy: a document's owner may read it. `alice` owns doc-1, `bob` owns doc-2.
 * const ownerCanRead = Policy.permit({
 *   id: "owner-can-read",
 *   action: Policy.eq(Entity.ref("Action", "doc:read")),
 *   when: Condition.eq(Condition.attr("resource", "owner"), Condition.principal),
 * })
 * const alice = Entity.ref("User", "alice")
 * const bob = Entity.ref("User", "bob")
 * const authorizerLayer = Authorizer.layer({ policies: [ownerCanRead] }).pipe(
 *   Layer.provide(
 *     Layer.succeed(
 *       EntityResolver,
 *       memoryEntityResolver([
 *         Entity.entity(Entity.ref("Document", "doc-1"), {
 *           attributes: { owner: Entity.entityValue(alice) },
 *         }),
 *         Entity.entity(Entity.ref("Document", "doc-2"), {
 *           attributes: { owner: Entity.entityValue(bob) },
 *         }),
 *       ]),
 *     ),
 *   ),
 * )
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
 * const myServiceLayer = SessionService.layer({
 *   sessionExpiresIn: { activePeriod: 7 * 86_400_000, idlePeriod: 86_400_000 },
 * }).pipe(Layer.provideMerge(Layer.mergeAll(storeLayers, Hooks.Default)))
 *
 * const AppLayer = HttpApiBuilder.layer(DocsApi).pipe(
 *   Layer.provide(docsGroup),
 *   Layer.provide(Layer.mergeAll(RequireDocRead.layer, authLayer(), authorizerLayer)),
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
 * const signIn = (userId: string) =>
 *   Effect.gen(function* () {
 *     const now = new Date()
 *     users.set(userId, { id: userId, name: userId, createdAt: now, updatedAt: now, attributes: {} })
 *     const sessionService = yield* SessionService
 *     return (yield* sessionService.createSession(userId)).token
 *   }).pipe(Effect.provide(myServiceLayer))
 *
 * const aliceToken = await Effect.runPromise(signIn("alice"))
 * const bobToken = await Effect.runPromise(signIn("bob"))
 *
 * const { handler, dispose } = HttpRouter.toWebHandler(AppLayer)
 * const get = (path: string, token: string) =>
 *   handler(new Request(`http://localhost${path}`, { headers: { authorization: `Bearer ${token}` } }))
 * try {
 *   // Owners are served the handler for their own doc (it returns no body: 204).
 *   assert.equal((await get("/docs/doc-1", aliceToken)).status, 204)
 *   // Anyone else is refused with 403.
 *   assert.equal((await get("/docs/doc-2", aliceToken)).status, 403)
 *   assert.equal((await get("/docs/doc-2", bobToken)).status, 204)
 * } finally {
 *   await dispose()
 * }
 * ```
 *
 * @module http/authorization-middleware
 */

import * as Context from "effect/Context";
import * as Effect from "effect/Effect";
import * as Layer from "effect/Layer";
import * as P from "effect/Predicate";
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
 * @since 0.1.0
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
 * @since 0.1.0
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
  if (!P.isFunction(input)) return Effect.succeed(input);
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
 * @since 0.1.0
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
 * @since 0.1.0
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
 * The runtime key of a guard named `Id`:
 * `@effect-auth/AuthorizationMiddleware/<name>#<n>`, where `<n>` counts
 * factory calls, so two guards built with one name still get distinct tags.
 *
 * @since 0.1.0
 * @category models
 */
export type AuthorizationMiddlewareKey<Id extends string> =
  `@effect-auth/AuthorizationMiddleware/${Id}#${number}`;

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
 * `Id` is the guard's name, carried in the instance's `key`
 * ({@link AuthorizationMiddlewareKey}). It is what makes two guards with the
 * same `R` different types.
 *
 * @since 0.1.0
 * @category models
 */
export type AuthorizationMiddlewareInstance<
  R = never,
  Id extends string = string,
> = Context.ServiceClass.Shape<
  AuthorizationMiddlewareKey<Id>,
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
 * @since 0.1.0
 * @category models
 */
export interface AuthorizationMiddlewareClass<
  R = never,
  Id extends string = string,
> extends HttpApiMiddleware.ServiceClass<
  AuthorizationMiddlewareInstance<R, Id>,
  AuthorizationMiddlewareKey<Id>,
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
 * The message a rejected guard name resolves to. It is the parameter's type, so
 * a call with a bad name fails with this text as the expected type.
 */
type GuardNameError =
  "a guard name must be one non-empty string literal, not string, a template pattern or a union";

/**
 * The guard's name, when it is one non-empty string literal. A `string`, a
 * template pattern such as `` `${string}Guard` ``, a union, and `""` each resolve
 * to {@link GuardNameError} instead: the first three would widen the guard's
 * type to other guards' types, and the last names no guard. The parameter's
 * type then reads as that message, so the call-site error explains the rule.
 *
 * `any` resolves to `never`, so no argument (not even `any`) is accepted. The
 * `0 extends 1 & Id` test sits inside the distributive `Id extends string`
 * branch on purpose: placed outside it, inference from an `any` argument falls
 * back to a wide name and `any` type-checks again.
 */
type GuardName<Id extends string, All extends string = Id> = Id extends string
  ? 0 extends 1 & Id
    ? never
    : [All] extends [Id]
      ? { readonly [key: string]: 1 } extends Record<Id, 1>
        ? GuardNameError
        : Id extends ""
          ? GuardNameError
          : Id
      : GuardNameError
  : never;

/**
 * Build a route-level `HttpApiMiddleware` that gates the handler on
 * `Authorizer.authorize(input)` for the {@link CurrentPrincipal} already in
 * context.
 *
 * Attach the returned class with `.middleware(...)` to whichever
 * `HttpApiEndpoint`/`HttpApiGroup` the policy protects, and provide its
 * `.layer` alongside the application layer — mirroring how `AuthMiddleware`
 * and its `layer()` are attached (see the module example).
 *
 * **Naming.** `name` is the guard's type identity, so give each guard its own
 * name. It must be one non-empty string literal: a `string`, `any`, a template
 * pattern, a union or `""` is a compile error, because a widened name would
 * widen the guard's type and an empty one names no guard. Two guards built with
 * the same literal still share a type, and a wrong `.layer` between them
 * type-checks and then fails at runtime. The runtime tag is
 * `@effect-auth/AuthorizationMiddleware/<name>#<n>`, unique per call either way.
 *
 * **Composition order.** `CurrentPrincipal` is declared in `requires`, so a
 * consumer who forgets to also attach `AuthMiddleware` (or otherwise put
 * `CurrentPrincipal` in context — e.g. a service-to-service principal) gets a
 * compile error: the final `HttpApiBuilder.layer(...)` composition will still
 * demand `CurrentPrincipal` in its context requirements. That check is
 * necessary but not sufficient — it catches a *missing* provider, not a
 * *wrongly ordered* one. At runtime `CurrentPrincipal` must actually be
 * resolved by the time this middleware's handler runs. In an endpoint's
 * `.middleware()` chain a later entry runs first, so `AuthMiddleware` must be
 * listed after this guard: it then provides `CurrentPrincipal` before the guard
 * reads it. Listing the guard after `AuthMiddleware` runs the guard first, with
 * no per-request principal, and it decides for whatever `CurrentPrincipal` the
 * app layer happens to hold.
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
 * @since 0.1.0
 * @category constructors
 */
export const makeAuthorizationMiddleware = <const Id extends string, R = never>(
  name: Id & GuardName<Id>,
  input: AuthorizationMiddlewareInput<R>,
): AuthorizationMiddlewareClass<R, Id> => {
  const key: AuthorizationMiddlewareKey<Id> = `@effect-auth/AuthorizationMiddleware/${name}#${_nextMiddlewareId++}`;

  class AuthorizationMiddleware extends HttpApiMiddleware.Service<
    AuthorizationMiddleware,
    { requires: AuthorizationRequires<R> }
  >()(key, { error: S.ForbiddenError }) {
    /**
     * The `Layer` implementing this middleware instance. Provide it
     * alongside the application layer, next to wherever `AuthMiddleware`'s
     * `layer()` and `Authorizer.layer(...)` are provided.
     */
    static readonly layer: Layer.Layer<AuthorizationMiddleware> = Layer.succeed(
      AuthorizationMiddleware,
      Effect.fn("AuthorizationMiddleware")(function* (handler, _opts) {
        const authorizer = yield* Authorizer;
        const request = yield* HttpServerRequest.HttpServerRequest;
        // `R` may name a service the router provides per request (see
        // `AuthorizationRequires`); providing those from the request's own
        // context leaves only the rest of `R` required.
        const routerServices = yield* Effect.context<HttpRouter.Provided>();
        const authInput = yield* resolveAuthorizeInput(input, request).pipe(
          Effect.provide(routerServices),
        );

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

  return AuthorizationMiddleware;
};
