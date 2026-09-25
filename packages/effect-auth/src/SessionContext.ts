/**
 * The session-context seam: the context services that carry "who is this
 * execution", and the `Layer` constructors that provide them from an
 * **already-resolved** session.
 *
 * ### Why this is separate from the middleware
 *
 * `AuthMiddleware` does two things at once: it *resolves* a credential out of
 * an `HttpServerRequest`, and it *provides* the result to the handler. Only
 * the first half is HTTP-specific. An app that resolves the session at its own
 * edge — a SvelteKit `hooks.server.ts` that fills `event.locals`, a Worker
 * route that dispatches before any router runs, a test harness that says "run
 * this as this fixture user" — has the *result* already and needs only the
 * second half.
 *
 * This module is that second half. It owns the tags; `http/HttpMiddleware.ts`
 * re-exports them and provides them from a request, so the same `Effect` runs
 * unchanged under an `HttpApi` handler, under a hand-rolled edge, and under a
 * test.
 *
 * ### Which service should my code depend on?
 *
 * | Service               | Holds                      | Depend on it when |
 * | --------------------- | -------------------------- | ----------------- |
 * | {@link MaybeCurrentSession} | `Option<SessionWithUser>` | **read-path code** — anything that must run for anonymous callers *without failing* |
 * | {@link CurrentUser}   | `User`                     | code that already sits behind a required-auth gate |
 * | {@link CurrentSession}| `Session`                  | as above, when the session record itself is needed |
 *
 * `MaybeCurrentSession` is the one to reach for by default. "Signed out" is a
 * *value* there (`Option.none()`), so a predicate like "may this viewer see
 * deleted rows?" can answer `false` for an anonymous caller instead of failing
 * — which is most of a real read path. `CurrentUser` is the convenience for
 * the gated case, and `requireCurrentUser` is the derived accessor that turns
 * the anonymous branch into a typed failure.
 *
 * Every constructor here also provides `CurrentPrincipal`, so the policy
 * kernel (`Authorizer.check` / `authorize`, `protectedField`) works in all
 * three contexts without the call site restating who the principal is.
 *
 * @example Running gated code in a runtime that never saw an HTTP request
 * ```ts
 * import { Effect } from "effect"
 * import * as Auth from "@thomasfosterau/effect-auth"
 *
 * // `resolved` came from the app's own edge — `event.locals`, a service
 * // binding, a test fixture. No `HttpServerRequest` is involved.
 * const run = <A, E>(effect: Effect.Effect<A, E, Auth.MaybeCurrentSession>) =>
 *   effect.pipe(Effect.provide(Auth.SessionContext.layer(resolved)))
 * ```
 *
 * @module session-context
 */
import { Context, Effect, Layer, Option } from "effect";
import { CurrentCredential, CurrentPrincipal, type CredentialClass } from "./Authorizer.ts";
import * as Entity from "./Entity.ts";
import * as Errors from "./Errors.ts";
import type * as Types from "./Types.ts";

// ---------------------------------------------------------------------------
// Context services
// ---------------------------------------------------------------------------

/**
 * Context service that holds the authenticated `Session` for the current
 * execution.
 *
 * Provided by {@link authenticatedLayer}, {@link userSessionLayer}, and by the
 * required-auth `AuthMiddleware`. Absent for anonymous executions — read
 * {@link MaybeCurrentSession} when the caller may be signed out.
 *
 * @since 1.0.0
 * @category context
 */
export class CurrentSession extends Context.Service<CurrentSession, Types.Session>()(
  "@effect-auth/CurrentSession",
) {}

/**
 * Context service that holds the authenticated `User` for the current
 * execution.
 *
 * Provided by {@link authenticatedLayer}, {@link userLayer},
 * {@link userSessionLayer}, and by the required-auth `AuthMiddleware`. Absent
 * for anonymous executions — read {@link MaybeCurrentSession} (or
 * {@link currentUserOption}) when the caller may be signed out.
 *
 * @since 1.0.0
 * @category context
 */
export class CurrentUser extends Context.Service<CurrentUser, Types.User>()(
  "@effect-auth/CurrentUser",
) {}

/**
 * Context service that holds an `Option<SessionWithUser>`: the session-aware
 * read-path service.
 *
 * `Option.some(resolved)` when a session resolved, `Option.none()` when the
 * execution is anonymous. Unlike {@link CurrentUser}, "signed out" is a value
 * here rather than the absence of a service, so a predicate can branch on it
 * without an error channel.
 *
 * Provided by every constructor in this module that knows whether a session
 * exists, and by **both** `AuthMiddleware` and `OptionalAuthMiddleware` — so
 * an effect written against this service runs unchanged under required auth,
 * optional auth, and a non-HTTP edge.
 *
 * @since 1.0.0
 * @category context
 */
export class MaybeCurrentSession extends Context.Service<
  MaybeCurrentSession,
  Option.Option<Types.SessionWithUser>
>()("@effect-auth/MaybeCurrentSession") {}

// ---------------------------------------------------------------------------
// Principal derivation
// ---------------------------------------------------------------------------

/**
 * The authorization principal for a user: `User::"<user.id>"`.
 *
 * Exported so an app that provides the session context by hand derives the
 * principal exactly as the middleware does, rather than restating the entity
 * type string.
 *
 * @since 1.0.0
 * @category constructors
 */
export const principalOf = (user: Types.User): Entity.EntityRef => Entity.ref("User", user.id);

// ---------------------------------------------------------------------------
// Layer constructors
// ---------------------------------------------------------------------------

/**
 * How the caller got in, for the constructors below.
 *
 * Defaults to `"interactive"`: a session handed to a runtime by an app edge
 * came from a browser credential unless the edge says otherwise. Pass
 * `"machine"` when the request authenticated with an API key — a credential
 * changes *who* the request is, never *what* it may do, and the policy kernel
 * reads `CurrentCredential` to enforce exactly that.
 *
 * @since 1.0.0
 * @category models
 */
export interface CredentialOptions {
  readonly credentialClass?: CredentialClass;
}

/**
 * Provide the full authenticated context from an already-resolved session:
 * {@link CurrentSession}, {@link CurrentUser}, {@link MaybeCurrentSession}
 * (as `Option.some`), `CurrentPrincipal` and `CurrentCredential`.
 *
 * This is the constructor for "I resolved the session at my own edge and want
 * to run gated code as that viewer" — a SvelteKit load reading
 * `event.locals`, a Worker route that dispatched before the router, an
 * integration test running an effect as a fixture user.
 *
 * `CurrentCredential` is provided because the required-auth middleware provides
 * it: an effect that reads it has to run in all three contexts, which is the
 * whole point of this module. It defaults to `"interactive"` — see
 * {@link CredentialOptions}.
 *
 * @since 1.0.0
 * @category layers
 */
export const authenticatedLayer = (
  resolved: Types.SessionWithUser,
  options?: CredentialOptions,
): Layer.Layer<
  CurrentSession | CurrentUser | MaybeCurrentSession | CurrentPrincipal | CurrentCredential
> =>
  Layer.mergeAll(
    Layer.succeed(CurrentSession, resolved.session),
    Layer.succeed(CurrentUser, resolved.user),
    Layer.succeed(MaybeCurrentSession, Option.some(resolved)),
    Layer.succeed(CurrentPrincipal, principalOf(resolved.user)),
    Layer.succeed(CurrentCredential, options?.credentialClass ?? "interactive"),
  );

/**
 * Provide the anonymous context: {@link MaybeCurrentSession} as
 * `Option.none()`.
 *
 * Deliberately provides neither {@link CurrentUser} nor `CurrentPrincipal` —
 * there is no user and no principal, and inventing one would let gated code
 * type-check against a context that cannot satisfy it.
 *
 * @since 1.0.0
 * @category layers
 */
export const anonymousLayer: Layer.Layer<MaybeCurrentSession> = Layer.succeed(
  MaybeCurrentSession,
  Option.none(),
);

/**
 * Provide the read-path context from whatever the app's edge produced: a
 * resolved session, an `Option` of one, or `null`/`undefined`.
 *
 * Provides {@link MaybeCurrentSession} only. The richer services
 * ({@link CurrentUser}, `CurrentPrincipal`) are *conditional* on a session
 * having resolved, so they cannot appear in a static `Layer` type here — which
 * is the point: code provided this layer must handle the anonymous branch.
 * Use {@link authenticatedLayer} when the session is known to exist.
 *
 * @example
 * ```ts
 * // SvelteKit: `event.locals.session` is `SessionWithUser | null`
 * const context = SessionContext.layer(event.locals.session)
 * ```
 *
 * @since 1.0.0
 * @category layers
 */
export const layer = (
  resolved: Types.SessionWithUser | Option.Option<Types.SessionWithUser> | null | undefined,
): Layer.Layer<MaybeCurrentSession> => Layer.succeed(MaybeCurrentSession, toOption(resolved));

/**
 * Provide the authenticated context for a user with no session record:
 * {@link CurrentUser}, `CurrentPrincipal` and `CurrentCredential`.
 *
 * For contexts where a viewer exists but a session genuinely does not — a job
 * runner acting as a known user, a fixture viewer in a unit test.
 *
 * It deliberately does **not** provide {@link MaybeCurrentSession}: there is
 * no `SessionWithUser` to put in it, and filling it with a synthetic session
 * would be a lie that leaks (an invented `expiresAt` eventually gets read).
 * Read-path code written against `MaybeCurrentSession` therefore will not
 * compile against this layer — reach for {@link userSessionLayer} or
 * {@link authenticatedLayer} when that code has to run.
 *
 * @since 1.0.0
 * @category layers
 */
export const userLayer = (
  user: Types.User,
  options?: CredentialOptions,
): Layer.Layer<CurrentUser | CurrentPrincipal | CurrentCredential> =>
  Layer.mergeAll(
    Layer.succeed(CurrentUser, user),
    Layer.succeed(CurrentPrincipal, principalOf(user)),
    Layer.succeed(CurrentCredential, options?.credentialClass ?? "interactive"),
  );

/**
 * {@link authenticatedLayer} from the session and user as separate values, for
 * edges that carry them apart (`event.locals.session` + `event.locals.user`).
 *
 * @since 1.0.0
 * @category layers
 */
export const userSessionLayer = (
  session: Types.Session,
  user: Types.User,
  options?: CredentialOptions,
): Layer.Layer<
  CurrentSession | CurrentUser | MaybeCurrentSession | CurrentPrincipal | CurrentCredential
> => authenticatedLayer({ session, user }, options);

// ---------------------------------------------------------------------------
// Accessors
// ---------------------------------------------------------------------------

/**
 * Normalize the several shapes an app edge hands back — a resolved session, an
 * `Option`, `null`, `undefined` — into one `Option`.
 *
 * @since 1.0.0
 * @category conversions
 */
export const toOption = (
  resolved: Types.SessionWithUser | Option.Option<Types.SessionWithUser> | null | undefined,
): Option.Option<Types.SessionWithUser> => {
  if (resolved === null || resolved === undefined) return Option.none();
  // An `Option` is distinguishable from a `SessionWithUser` by its tag; a
  // resolved session is a plain struct with `session`/`user` keys.
  return Option.isOption(resolved) ? resolved : Option.some(resolved);
};

/**
 * The current user as an `Option` — the read-path accessor.
 *
 * Succeeds for anonymous executions with `Option.none()`, so a predicate can
 * branch without an error channel.
 *
 * @since 1.0.0
 * @category accessors
 */
export const currentUserOption: Effect.Effect<
  Option.Option<Types.User>,
  never,
  MaybeCurrentSession
> = MaybeCurrentSession.useSync(Option.map((resolved) => resolved.user));

/**
 * The current session as an `Option` — the read-path accessor.
 *
 * @since 1.0.0
 * @category accessors
 */
export const currentSessionOption: Effect.Effect<
  Option.Option<Types.Session>,
  never,
  MaybeCurrentSession
> = MaybeCurrentSession.useSync(Option.map((resolved) => resolved.session));

/**
 * Whether a session resolved for the current execution.
 *
 * @since 1.0.0
 * @category accessors
 */
export const isAuthenticated: Effect.Effect<boolean, never, MaybeCurrentSession> =
  MaybeCurrentSession.useSync(Option.isSome);

/**
 * The current user, failing with `NotAuthenticatedError` when the execution is
 * anonymous.
 *
 * The derived convenience over {@link MaybeCurrentSession} — the failing
 * accessor, not the underlying service. Prefer {@link currentUserOption} on a
 * read path that must serve anonymous callers.
 *
 * @since 1.0.0
 * @category accessors
 */
export const requireCurrentUser: Effect.Effect<
  Types.User,
  Errors.NotAuthenticatedError,
  MaybeCurrentSession
> = Effect.flatMap(currentUserOption, (user) =>
  Option.isSome(user)
    ? Effect.succeed(user.value)
    : Effect.fail(new Errors.NotAuthenticatedError({ message: "Not authenticated" })),
);

/**
 * The current session, failing with `NotAuthenticatedError` when the execution
 * is anonymous.
 *
 * @since 1.0.0
 * @category accessors
 */
export const requireCurrentSession: Effect.Effect<
  Types.Session,
  Errors.NotAuthenticatedError,
  MaybeCurrentSession
> = Effect.flatMap(currentSessionOption, (session) =>
  Option.isSome(session)
    ? Effect.succeed(session.value)
    : Effect.fail(new Errors.NotAuthenticatedError({ message: "Not authenticated" })),
);

// ---------------------------------------------------------------------------
// The application's viewer (generic in its own user type)
// ---------------------------------------------------------------------------

/**
 * Provide an application-declared viewer service from whatever the edge
 * produced: the app's own user, an `Option` of one, or `null` / `undefined`
 * for anonymous.
 *
 * The viewer service is the application's, not this library's, because its
 * user type is: an app declares
 * `class CurrentViewer extends Context.Service<CurrentViewer, Option.Option<AppUser>>()("@app/CurrentViewer") {}`
 * with `AppUser extends { id: string; role: string }`, hands it to
 * `Guard.make`, and every gate then yields `AppUser` — no inference twin, no
 * `attributes["role"] as string` at call sites.
 *
 * @example
 * ```ts
 * import { Context, Option } from "effect"
 * import * as Auth from "@thomasfosterau/effect-auth"
 *
 * interface AppUser { readonly id: string; readonly role: string }
 * class CurrentViewer extends Context.Service<CurrentViewer, Option.Option<AppUser>>()(
 *   "@app/CurrentViewer",
 * ) {}
 *
 * // A job or a test running as a known account:
 * const asModerator = Auth.SessionContext.viewerLayer(CurrentViewer, { id: "u1", role: "moderator" })
 * // …and as nobody:
 * const asAnonymous = Auth.SessionContext.viewerLayer(CurrentViewer, null)
 * ```
 *
 * @since 1.0.0
 * @category layers
 */
export const viewerLayer = <Id, User>(
  viewer: Context.Key<Id, Option.Option<User>>,
  user: User | Option.Option<User> | null | undefined,
): Layer.Layer<Id> =>
  Layer.succeed(
    viewer,
    user === null || user === undefined
      ? Option.none()
      : Option.isOption(user)
        ? (user as Option.Option<User>)
        : Option.some(user as User),
  );

/**
 * Provide an application-declared viewer service from the resolved session
 * ({@link MaybeCurrentSession}), projecting this library's `SessionWithUser`
 * into the app's user type. Anonymous stays anonymous; a projection that
 * answers `none` makes the viewer anonymous too.
 *
 * {@link withRole} is the projection for a deployment that keeps the rung in
 * the user's `attributes`.
 *
 * @since 1.0.0
 * @category layers
 */
export const viewerFromSession = <Id, User>(
  viewer: Context.Key<Id, Option.Option<User>>,
  project: (resolved: Types.SessionWithUser) => Option.Option<User>,
): Layer.Layer<Id, never, MaybeCurrentSession> =>
  Layer.effect(viewer, MaybeCurrentSession.useSync(Option.flatMap(project)));

/**
 * The library's `User` with its rung lifted out of `attributes` — the viewer
 * shape `Guard.make` needs, for a deployment that stores the rung as a user
 * attribute.
 *
 * @since 1.0.0
 * @category models
 */
export type UserWithRole = Types.User & { readonly role: string };

/**
 * A {@link viewerFromSession} projection that reads the rung from
 * `user.attributes[attribute]` (default `"role"`).
 *
 * A signed-in user with no string there is still signed in — `requireUser`
 * admits them — but holds no rung: the role is the empty string, which is on
 * no ladder, so every rung gate refuses them (fail closed).
 *
 * @since 1.0.0
 * @category conversions
 */
export const withRole =
  (attribute = "role") =>
  (resolved: Types.SessionWithUser): Option.Option<UserWithRole> => {
    const role = resolved.user.attributes[attribute];
    return Option.some({ ...resolved.user, role: typeof role === "string" ? role : "" });
  };
