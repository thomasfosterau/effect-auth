/**
 * Run an `Effect` as a fixture principal in one call, so an application tests
 * its own guards, policies and session-aware read paths without HTTP.
 *
 * Two shapes, matching the two ways an app names its viewer:
 *
 * - {@link runAs} takes this library's `User` and provides the session
 *   context exactly as the required-auth middleware does: `CurrentSession`,
 *   `CurrentUser`, `MaybeCurrentSession`, `CurrentPrincipal` and
 *   `CurrentCredential`. Passing `null` provides the anonymous context
 *   (`MaybeCurrentSession` as `none`) and nothing else.
 * - {@link runAsViewer} takes the application's own viewer service (the one
 *   handed to `Guard.make`) and the app's user, and provides that viewer through
 *   `SessionContext.viewerLayer` alongside the same session context, so `Guard`
 *   gates, `Authorizer` decisions and `SessionContext` accessors all see the
 *   one fixture principal.
 *
 * The fixture session is minted from the `Clock` when the layer is built: it
 * started now and expires in 24 hours, so it is valid under `TestClock` too.
 *
 * @module testing
 */
import { type Context, DateTime, Effect, Layer, type Option, Schema } from "effect";
import type { CredentialClass, CurrentCredential, CurrentPrincipal } from "../Authorizer.ts";
import * as SessionContext from "../SessionContext.ts";
import type * as Types from "../Types.ts";

/**
 * Everything {@link layerAs} provides for a signed-in fixture: the same
 * services the required-auth middleware provides.
 *
 * @since 1.0.0
 * @category models
 */
export type AuthenticatedServices =
  | SessionContext.CurrentSession
  | SessionContext.CurrentUser
  | SessionContext.MaybeCurrentSession
  | CurrentPrincipal
  | CurrentCredential;

/**
 * How the fixture principal got in, and what its session looks like.
 *
 * @since 1.0.0
 * @category models
 */
export interface RunAsOptions {
  /** Defaults to `"interactive"`; pass `"machine"` to run as an API key would. */
  readonly credentialClass?: CredentialClass | undefined;
  /**
   * Fields of the fixture session to override. `userId` always follows the
   * user.
   */
  readonly session?: Partial<Omit<Types.Session, "userId">> | undefined;
}

const sessionLifetimeMillis = 24 * 60 * 60 * 1000;

const decodeMillis = Schema.decodeUnknownEffect(Schema.DateFromMillis);

/**
 * A fixture session for `user`, started at `now` and expiring 24 hours later.
 *
 * Fails with a `SchemaError` when `now` is an Invalid Date (or the expiry
 * falls outside the `Date` range), rather than building a session whose
 * instants are Invalid Dates.
 *
 * @since 1.0.0
 * @category constructors
 */
export const sessionFor = (
  user: Types.User,
  now: Date,
  overrides?: Partial<Omit<Types.Session, "userId">> | undefined,
): Effect.Effect<Types.SessionWithUser, Schema.SchemaError> =>
  Effect.map(decodeMillis(now.getTime() + sessionLifetimeMillis), (expiresAt) => ({
    session: {
      id: `fixture-session-${user.id}`,
      expiresAt,
      createdAt: now,
      lastActivityAt: now,
      attributes: {},
      ...overrides,
      userId: user.id,
    },
    user,
  }));

const authenticated = (
  user: (now: Date) => Types.User,
  options: RunAsOptions | undefined,
): Layer.Layer<AuthenticatedServices> =>
  Layer.unwrap(
    DateTime.nowAsDate.pipe(
      // The Clock's own instant is always a valid Date, so a failure here is a
      // defect rather than an expected error.
      Effect.flatMap((now) => sessionFor(user(now), now, options?.session)),
      Effect.orDie,
      Effect.map((sessionWithUser) =>
        SessionContext.authenticatedLayer(sessionWithUser, {
          credentialClass: options?.credentialClass ?? "interactive",
        }),
      ),
    ),
  );

/**
 * The session context for a fixture principal, as a layer: the anonymous
 * context for `null` / `undefined`, the full authenticated context for a user.
 *
 * @since 1.0.0
 * @category layers
 */
export function layerAs(user: null | undefined): Layer.Layer<SessionContext.MaybeCurrentSession>;
export function layerAs(
  user: Types.User,
  options?: RunAsOptions,
): Layer.Layer<AuthenticatedServices>;
export function layerAs(
  user: Types.User | null | undefined,
  options?: RunAsOptions,
): Layer.Layer<AuthenticatedServices> | Layer.Layer<SessionContext.MaybeCurrentSession>;
export function layerAs(
  user: Types.User | null | undefined,
  options?: RunAsOptions,
): Layer.Layer<AuthenticatedServices> | Layer.Layer<SessionContext.MaybeCurrentSession> {
  return user === null || user === undefined
    ? SessionContext.anonymousLayer
    : authenticated(() => user, options);
}

/**
 * Run an effect as a fixture user, or anonymously for `null` / `undefined`.
 *
 * Signed in, the effect sees the same services the required-auth middleware
 * provides ({@link AuthenticatedServices}). Anonymous, it sees only
 * `MaybeCurrentSession` as `none`, so an effect that needs `CurrentUser` or
 * `CurrentPrincipal` does not type-check against it, just as it would not
 * compile behind optional auth.
 *
 * @example
 * ```ts
 * import assert from "node:assert/strict"
 * import { Effect } from "effect"
 * import { SessionContext, type User } from "@thomasfosterau/effect-auth"
 * import * as Testing from "@thomasfosterau/effect-auth/testing"
 *
 * const now = new Date()
 * const ada: User = { id: "u-ada", createdAt: now, updatedAt: now, attributes: {} }
 *
 * const greeting = Effect.map(SessionContext.currentUserOption, (user) =>
 *   user._tag === "Some" ? `hello ${user.value.id}` : "hello stranger",
 * )
 *
 * assert.equal(await Effect.runPromise(greeting.pipe(Testing.runAs(ada))), "hello u-ada")
 * assert.equal(await Effect.runPromise(greeting.pipe(Testing.runAs(null))), "hello stranger")
 * ```
 *
 * @since 1.0.0
 * @category combinators
 */
export function runAs(
  user: null | undefined,
): <A, E, R>(
  effect: Effect.Effect<A, E, R>,
) => Effect.Effect<A, E, Exclude<R, SessionContext.MaybeCurrentSession>>;
export function runAs(
  user: Types.User,
  options?: RunAsOptions,
): <A, E, R>(
  effect: Effect.Effect<A, E, R>,
) => Effect.Effect<A, E, Exclude<R, AuthenticatedServices>>;
export function runAs(
  user: Types.User | null | undefined,
  options?: RunAsOptions,
): <A, E, R>(
  effect: Effect.Effect<A, E, R>,
) => Effect.Effect<A, E, Exclude<R, SessionContext.MaybeCurrentSession>>;
export function runAs(
  user: Types.User | null | undefined,
  options?: RunAsOptions,
):
  | (<A, E, R>(
      effect: Effect.Effect<A, E, R>,
    ) => Effect.Effect<A, E, Exclude<R, AuthenticatedServices>>)
  | (<A, E, R>(
      effect: Effect.Effect<A, E, R>,
    ) => Effect.Effect<A, E, Exclude<R, SessionContext.MaybeCurrentSession>>) {
  if (user === null || user === undefined) {
    return (effect) => Effect.provide(effect, SessionContext.anonymousLayer);
  }
  const context = layerAs(user, options);
  return (effect) => Effect.provide(effect, context);
}

/**
 * The least an application's viewer must carry for {@link runAsViewer}: an id,
 * which becomes the fixture's `User::"<id>"` principal.
 *
 * @since 1.0.0
 * @category models
 */
export interface ViewerFixture {
  readonly id: string;
}

/**
 * {@link RunAsOptions}, plus how the app's viewer becomes this library's
 * `User`.
 *
 * @since 1.0.0
 * @category models
 */
export interface ViewerOptions<User> extends RunAsOptions {
  /**
   * Project the app's viewer into this library's `User`. By default the user
   * keeps the viewer's `id`, was created `now`, and carries every other field
   * of the viewer as an attribute, so `SessionContext.withRole()` reads the
   * same `role` the app's viewer holds.
   */
  readonly toUser?: ((viewer: User, now: Date) => Types.User) | undefined;
}

const defaultToUser = <User extends ViewerFixture>(viewer: User, now: Date): Types.User => {
  const { id, ...attributes } = viewer;
  return { id, createdAt: now, updatedAt: now, attributes };
};

/**
 * {@link layerAs} for the application's own viewer service: provides the
 * viewer through `SessionContext.viewerLayer`, and the session context for
 * the same principal.
 *
 * @since 1.0.0
 * @category layers
 */
export function viewerLayerAs<Id, User extends ViewerFixture>(
  viewer: Context.Key<Id, Option.Option<User>>,
  user: null | undefined,
): Layer.Layer<Id | SessionContext.MaybeCurrentSession>;
export function viewerLayerAs<Id, User extends ViewerFixture>(
  viewer: Context.Key<Id, Option.Option<User>>,
  user: NoInfer<User>,
  options?: ViewerOptions<NoInfer<User>>,
): Layer.Layer<Id | AuthenticatedServices>;
export function viewerLayerAs<Id, User extends ViewerFixture>(
  viewer: Context.Key<Id, Option.Option<User>>,
  user: NoInfer<User> | null | undefined,
  options?: ViewerOptions<NoInfer<User>>,
): Layer.Layer<Id | AuthenticatedServices> | Layer.Layer<Id | SessionContext.MaybeCurrentSession>;
export function viewerLayerAs<Id, User extends ViewerFixture>(
  viewer: Context.Key<Id, Option.Option<User>>,
  user: User | null | undefined,
  options?: ViewerOptions<User>,
): Layer.Layer<Id | AuthenticatedServices> | Layer.Layer<Id | SessionContext.MaybeCurrentSession> {
  const viewerContext = SessionContext.viewerLayer(viewer, user);
  if (user === null || user === undefined) {
    return Layer.merge(viewerContext, SessionContext.anonymousLayer);
  }
  const toUser = options?.toUser ?? defaultToUser;
  return Layer.merge(
    viewerContext,
    authenticated((now) => toUser(user, now), options),
  );
}

/**
 * Run an effect as a fixture viewer of the application's own viewer service,
 * or anonymously for `null` / `undefined`.
 *
 * The one call an app needs to test its `Guard` gates: the viewer service is
 * provided through `SessionContext.viewerLayer`, and the session context for
 * the same principal alongside it (see {@link runAs}), so a gate, a policy
 * decision and a session accessor all agree on who is asking.
 *
 * @example
 * ```ts
 * import assert from "node:assert/strict"
 * import { Context, Effect, Exit, Option } from "effect"
 * import * as Auth from "@thomasfosterau/effect-auth"
 * import * as Testing from "@thomasfosterau/effect-auth/testing"
 *
 * interface AppUser { readonly id: string; readonly role: string }
 * class CurrentViewer extends Context.Service<CurrentViewer, Option.Option<AppUser>>()(
 *   "@app/CurrentViewer",
 * ) {}
 *
 * const Roles = Auth.Ladder.make(["user", "moderator"])
 * const guards = Auth.Guard.make({ ladder: Roles, viewer: CurrentViewer })
 * const moderate = guards.requireRoleAtLeast("moderator")
 *
 * const asModerator = moderate.pipe(
 *   Testing.runAsViewer(CurrentViewer, { id: "u-1", role: "moderator" }),
 * )
 * const asMember = moderate.pipe(Testing.runAsViewer(CurrentViewer, { id: "u-2", role: "user" }))
 * const asNobody = moderate.pipe(Testing.runAsViewer(CurrentViewer, null))
 *
 * assert.ok(Exit.isSuccess(await Effect.runPromiseExit(asModerator)))
 * assert.ok(Exit.isFailure(await Effect.runPromiseExit(asMember)))
 * assert.ok(Exit.isFailure(await Effect.runPromiseExit(asNobody)))
 * ```
 *
 * @since 1.0.0
 * @category combinators
 */
export function runAsViewer<Id, User extends ViewerFixture>(
  viewer: Context.Key<Id, Option.Option<User>>,
  user: null | undefined,
): <A, E, R>(
  effect: Effect.Effect<A, E, R>,
) => Effect.Effect<A, E, Exclude<R, Id | SessionContext.MaybeCurrentSession>>;
export function runAsViewer<Id, User extends ViewerFixture>(
  viewer: Context.Key<Id, Option.Option<User>>,
  user: NoInfer<User>,
  options?: ViewerOptions<NoInfer<User>>,
): <A, E, R>(
  effect: Effect.Effect<A, E, R>,
) => Effect.Effect<A, E, Exclude<R, Id | AuthenticatedServices>>;
export function runAsViewer<Id, User extends ViewerFixture>(
  viewer: Context.Key<Id, Option.Option<User>>,
  user: NoInfer<User> | null | undefined,
  options?: ViewerOptions<NoInfer<User>>,
): <A, E, R>(
  effect: Effect.Effect<A, E, R>,
) => Effect.Effect<A, E, Exclude<R, Id | SessionContext.MaybeCurrentSession>>;
export function runAsViewer<Id, User extends ViewerFixture>(
  viewer: Context.Key<Id, Option.Option<User>>,
  user: User | null | undefined,
  options?: ViewerOptions<User>,
):
  | (<A, E, R>(
      effect: Effect.Effect<A, E, R>,
    ) => Effect.Effect<A, E, Exclude<R, Id | AuthenticatedServices>>)
  | (<A, E, R>(
      effect: Effect.Effect<A, E, R>,
    ) => Effect.Effect<A, E, Exclude<R, Id | SessionContext.MaybeCurrentSession>>) {
  const viewerContext = SessionContext.viewerLayer(viewer, user);
  if (user === null || user === undefined) {
    const context = Layer.merge(viewerContext, SessionContext.anonymousLayer);
    return (effect) => Effect.provide(effect, context);
  }
  const context = viewerLayerAs(viewer, user, options);
  return (effect) => Effect.provide(effect, context);
}
