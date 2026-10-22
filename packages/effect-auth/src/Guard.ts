/**
 * Zero-IO guards over an already-resolved viewer: the gates (`requireUser`,
 * `requireRoleAtLeast`, `requireOwnerOrRole`), their never-failing predicate
 * counterparts, and the per-viewer capability hooks that restate a write gate
 * as `meta.canEdit` / `canDelete`.
 *
 * ### The kernel's fast path, not a second engine
 *
 * Every rung and ownership decision here is made by `Policy.decidePure` over a
 * slice built from facts the caller already holds — the viewer's id and rung,
 * and (for ownership) the owner id the caller loaded with the row. No
 * `EntityResolver`, no `Authorizer`, no IO. The policies decided are the ones
 * {@link Guards.policies} returns, which are ordinary `DeclarativePolicy`
 * values: a gate and a stored declarative policy built from the same axis
 * cannot disagree, because they are the same value (ADR-0018: there is one
 * authorization model).
 *
 * ### Gates and predicates
 *
 * - **Gates** fail: anonymous → {@link Unauthorized}, signed in but not
 *   entitled → {@link Forbidden}. They yield the viewer on success, so a gate
 *   is the first line of an operation: `const user = yield* guards.requireUser`.
 * - **Predicates** never fail and treat anonymous as an ordinary answer
 *   (`false`). Most of a read path, and all per-viewer response shaping, is
 *   predicates.
 *
 * Gates are Effect **values** where they take no argument (`requireUser`), so
 * call sites yield them bare; the axis-taking ones are functions, and an app
 * binds its named gates once: `const requireModerator =
 * guards.requireRoleAtLeast(Axes.moderate)`.
 *
 * ### 401, 403 — and 404
 *
 * | Outcome                                   | Status | Error                   |
 * | ----------------------------------------- | ------ | ----------------------- |
 * | no viewer, on a gated **write**           | 401    | {@link Unauthorized}    |
 * | a viewer below the gate, on a **write**   | 403    | {@link Forbidden}       |
 * | a **read** predicate answers `false`      | **404**| the app's `NotFound`    |
 *
 * The last row is the one to get right. A read the viewer may not see must be
 * indistinguishable from a read of a row that does not exist: answering 403
 * confirms the row exists, which is an enumeration oracle. So read paths ask a
 * predicate (`canViewOwned`, `hasRoleAtLeast`) and turn `false` into the same
 * not-found they return for a missing id — never into `Forbidden`.
 *
 * ### Users and system principals
 *
 * The kit's gates admit a viewer and nothing else: a background job has no
 * viewer, so it cannot pass them. {@link requireSystem} is the gate for a job:
 * it admits the {@link Authorizer.CurrentPrincipal} when that is a system
 * principal (`System::"<name>"`) a policy grants the action, decides it through
 * the `Authorizer` (so the decision is logged with the job's name), and yields
 * its `EntityRef`. An operation either may perform asks which it has: the user
 * gate when a viewer is signed in, the system gate otherwise. Report the write
 * with `recordWrite`, naming whichever principal passed, and `AuditPlugin`
 * logs it.
 *
 * ```ts
 * import assert from "node:assert/strict"
 * import { Context, Effect, Layer, Option, Result } from "effect"
 * import * as Auth from "@thomasfosterau/effect-auth"
 *
 * interface AppUser { readonly id: string; readonly role: string }
 * class CurrentViewer extends Context.Service<CurrentViewer, Option.Option<AppUser>>()(
 *   "@app/CurrentViewer",
 * ) {}
 *
 * const Roles = Auth.Ladder.make(["user", "contributor"])
 * const guards = Auth.Guard.make({ ladder: Roles, viewer: CurrentViewer })
 * const requireContributor = guards.requireRoleAtLeast("contributor")
 *
 * // The translation pipeline may write pages, and nothing else.
 * const AuthorizerLive = Auth.Authorizer.layer({
 *   policies: [
 *     Auth.System.grant("translation-pipeline", {
 *       id: "translation-pipeline:write-pages",
 *       action: "page:write",
 *       resource: Auth.Policy.isType("Page"),
 *     }),
 *   ],
 * })
 *
 * const writePage = (id: string) =>
 *   Effect.gen(function* () {
 *     const resource = Auth.Entity.ref("Page", id)
 *     const actor = (yield* guards.isSignedIn)
 *       ? guards.principal(yield* requireContributor).ref
 *       : yield* Auth.Guard.requireSystem({ action: "page:write", resource })
 *     // ...the write itself...
 *     yield* Auth.recordWrite({ principal: actor, action: "page:write", resource })
 *     return Auth.Entity.formatRef(actor)
 *   })
 *
 * const anonymous = Layer.succeed(CurrentViewer, Option.none())
 * const ada = Layer.succeed(CurrentViewer, Option.some({ id: "u-1", role: "contributor" }))
 *
 * const program = Effect.gen(function* () {
 *   assert.equal(yield* writePage("p-1").pipe(Effect.provide(ada)), 'User::"u-1"')
 *   assert.equal(
 *     yield* writePage("p-1").pipe(Auth.System.provide("translation-pipeline"), Effect.provide(anonymous)),
 *     'System::"translation-pipeline"',
 *   )
 *   // A job no policy grants is refused.
 *   const refused = yield* Effect.result(
 *     writePage("p-1").pipe(Auth.System.provide("billing-cron"), Effect.provide(anonymous)),
 *   )
 *   assert.ok(Result.isFailure(refused))
 * }).pipe(Effect.provide(Layer.merge(AuthorizerLive, Auth.Hooks.Default)))
 *
 * await Effect.runPromise(program)
 * ```
 *
 * ### "Signed in" is not a rung
 *
 * `requireUser` asks whether a viewer exists and compares no rung. It is
 * deliberately not `requireRoleAtLeast(lowestRung)`: the two diverge the
 * instant the ladder gains a rung below the lowest one.
 *
 * @example
 * ```ts
 * import assert from "node:assert/strict"
 * import { Context, Effect, Layer, Option, Result } from "effect"
 * import * as Auth from "@thomasfosterau/effect-auth"
 *
 * interface AppUser { readonly id: string; readonly role: string; readonly name: string }
 * class CurrentViewer extends Context.Service<CurrentViewer, Option.Option<AppUser>>()(
 *   "@app/CurrentViewer",
 * ) {}
 *
 * const Roles = Auth.Ladder.make(["user", "contributor", "moderator", "admin"])
 * const Axes = Roles.axes({ corpusWrite: "contributor", moderate: "moderator" })
 * const guards = Auth.Guard.make({ ladder: Roles, viewer: CurrentViewer })
 *
 * const requireContributor = guards.requireRoleAtLeast(Axes.corpusWrite)
 *
 * const renameTaxon = (id: string, name: string) =>
 *   Effect.gen(function* () {
 *     const user = yield* requireContributor // Unauthorized | Forbidden
 *     return { id, name, editedBy: user.id }
 *   })
 *
 * const viewedBy = (user: AppUser) => Layer.succeed(CurrentViewer, Option.some(user))
 *
 * const program = Effect.gen(function* () {
 *   const ada = { id: "u-1", role: "contributor", name: "Ada" }
 *   const grace = { id: "u-2", role: "user", name: "Grace" }
 *
 *   const renamed = yield* renameTaxon("t-1", "Birds").pipe(Effect.provide(viewedBy(ada)))
 *   assert.deepEqual(renamed, { id: "t-1", name: "Birds", editedBy: "u-1" })
 *
 *   // A signed-in user below the contributor rung is refused.
 *   const refused = yield* Effect.result(renameTaxon("t-1", "Birds").pipe(Effect.provide(viewedBy(grace))))
 *   assert.ok(Result.isFailure(refused))
 * })
 *
 * await Effect.runPromise(program)
 * ```
 *
 * @module guard
 */
import { Context, Data, Effect, Option, Predicate, Schema } from "effect";
import * as Authorizer from "./Authorizer.ts";
import * as Condition from "./Condition.ts";
import type * as Errors from "./Errors.ts";
import * as Entity from "./Entity.ts";
import type * as Ladder from "./Ladder.ts";
import * as Policy from "./Policy.ts";

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

/**
 * 401 — the operation needs a viewer and there is none.
 *
 * The same class the HTTP tier's error schemas carry (`Http` re-exports it),
 * so a guard's failure encodes at the edge with no translation.
 *
 * @since 1.0.0
 * @category errors
 */
export class Unauthorized extends Schema.TaggedError<Unauthorized>()("Unauthorized", {
  message: Schema.String,
  code: Schema.optional(Schema.String),
}) {}

/**
 * 403 — there is a viewer, and the gate refuses them. Never the answer to a
 * **read** the viewer may not see (that is a 404; see the module docs).
 *
 * @since 1.0.0
 * @category errors
 */
export class Forbidden extends Schema.TaggedError<Forbidden>()("Forbidden", {
  message: Schema.String,
  code: Schema.optional(Schema.String),
}) {}

// ---------------------------------------------------------------------------
// The viewer
// ---------------------------------------------------------------------------

/**
 * What the guards need of a viewer: an id and one rung. The application's own
 * user type is kept intact through every gate — `requireUser` yields `User`,
 * not this shape.
 *
 * @since 1.0.0
 * @category models
 */
export interface ViewerShape {
  readonly id: string;
  readonly role: string;
}

/**
 * The capability `meta` a per-viewer hook computes: whether the viewer may
 * edit and delete the resource. Advisory — it drives whether a client renders
 * a control; the write path still runs its gate.
 *
 * @since 1.0.0
 * @category models
 */
export interface Capabilities {
  readonly canEdit: boolean;
  readonly canDelete: boolean;
}

/**
 * The guard kit for one viewer service and one ladder. Build it with
 * {@link make}.
 *
 * @since 1.0.0
 * @category models
 */
export interface Guards<Id, User extends ViewerShape, Rung extends string> {
  /** The ladder the kit compares against. */
  readonly ladder: Ladder.Ladder<Rung>;
  /** The resolved viewer, `Option.none()` when anonymous. Never fails. */
  readonly viewer: Effect.Effect<Option.Option<User>, never, Id>;
  /**
   * The viewer as the kernel's principal entity — `<principalType>::"<id>"`
   * carrying the rung as its `role` attribute. Exposed so a module deciding
   * over the same slice shape (`OwnedAccess`) builds it identically.
   */
  readonly principal: (viewer: User) => Entity.Entity;
  /** The entity type {@link Guards.principal} builds. */
  readonly principalType: string;

  // -- gates ---------------------------------------------------------------

  /** The viewer, failing `Unauthorized` when anonymous. Compares no rung. */
  readonly requireUser: Effect.Effect<User, Unauthorized, Id>;
  /** The viewer when they hold `min` or above; `Unauthorized` / `Forbidden` otherwise. */
  readonly requireRoleAtLeast: (
    min: NoInfer<Rung> | Ladder.Axis<NoInfer<Rung>>,
  ) => Effect.Effect<User, Unauthorized | Forbidden, Id>;
  /**
   * The owned-material write gate: the viewer when they own the row
   * (`user.id === ownerId`) or hold `min` or above. `ownerId` is the one fact
   * the caller already loaded with the row; nothing else is fetched.
   */
  readonly requireOwnerOrRole: (
    ownerId: string,
    min: NoInfer<Rung> | Ladder.Axis<NoInfer<Rung>>,
  ) => Effect.Effect<User, Unauthorized | Forbidden, Id>;

  // -- predicates ----------------------------------------------------------

  /** Whether a viewer is present. */
  readonly isSignedIn: Effect.Effect<boolean, never, Id>;
  /** Whether the viewer holds `min` or above; `false` when anonymous. */
  readonly hasRoleAtLeast: (
    min: NoInfer<Rung> | Ladder.Axis<NoInfer<Rung>>,
  ) => Effect.Effect<boolean, never, Id>;
  /** Whether the viewer owns the row or holds `min` or above; `false` when anonymous. */
  readonly isOwnerOrRole: (
    ownerId: string,
    min: NoInfer<Rung> | Ladder.Axis<NoInfer<Rung>>,
  ) => Effect.Effect<boolean, never, Id>;

  // -- pure decisions (the kit's kernel calls, for a viewer already in hand) --

  /** {@link Guards.hasRoleAtLeast} for a viewer the caller already holds. */
  readonly decideRole: (
    viewer: User | null | undefined,
    min: NoInfer<Rung> | Ladder.Axis<NoInfer<Rung>>,
  ) => boolean;
  /** {@link Guards.isOwnerOrRole} for a viewer the caller already holds. */
  readonly decideOwnerOrRole: (
    viewer: User | null | undefined,
    ownerId: string | undefined,
    min: NoInfer<Rung> | Ladder.Axis<NoInfer<Rung>>,
  ) => boolean;

  // -- capability hooks ----------------------------------------------------

  /**
   * The capability hook for a family whose write gate is a rung and nothing
   * else: `canEdit` / `canDelete` both answer {@link Guards.decideRole}.
   * Take `min` from the same axis the operation's gate names, so moving the
   * capability moves the `meta` with it.
   */
  readonly roleCapabilities: (
    min: NoInfer<Rung> | Ladder.Axis<NoInfer<Rung>>,
  ) => (viewer: User | null | undefined) => Capabilities;
  /**
   * The capability hook for owned material: the owner, or `min` and above —
   * exactly {@link Guards.requireOwnerOrRole}, restated as `meta`. `ownerOf`
   * reads the owner id off the representation; a resource with no owner
   * advertises nothing a non-privileged viewer could act on.
   */
  readonly ownedCapabilities: <Resource>(
    min: NoInfer<Rung> | Ladder.Axis<NoInfer<Rung>>,
    ownerOf: (resource: Resource) => string | undefined,
  ) => (resource: Resource, viewer: User | null | undefined) => Capabilities;

  // -- the policies the kit decides ----------------------------------------

  /**
   * The declarative policies behind the gates — store them, validate them
   * against an `AuthorizationModel`, or hand them to an `Authorizer`; they are
   * the values the gates decide, not copies.
   *
   * They are action-agnostic by design: a gate answers "may this viewer act
   * here at all", so each permit has no action scope and allows every action
   * to a viewer at the rung (or the owner). Handed to an `Authorizer` that also
   * decides individual actions, they grant all of them. Scope your own
   * per-action permits for that (as `OwnedAccess.policies` scopes its permits
   * to `Action::"read"`).
   */
  readonly policies: {
    readonly roleAtLeast: (
      min: NoInfer<Rung> | Ladder.Axis<NoInfer<Rung>>,
    ) => ReadonlyArray<Policy.DeclarativePolicy>;
    readonly ownerOrRole: (
      min: NoInfer<Rung> | Ladder.Axis<NoInfer<Rung>>,
    ) => ReadonlyArray<Policy.DeclarativePolicy>;
  };
}

/**
 * Options for {@link make}.
 *
 * @since 1.0.0
 * @category models
 */
export interface GuardOptions<Id, User extends ViewerShape, Rung extends string> {
  readonly ladder: Ladder.Ladder<Rung>;
  /**
   * The application's viewer service: `Option<User>`, `none` when anonymous.
   * Provide it with `SessionContext.viewerLayer` /
   * `SessionContext.viewerFromSession`.
   */
  readonly viewer: Context.Key<Id, Option.Option<User>>;
  /**
   * The principal's entity type in the decision slice. Defaults to `"User"`.
   * `"System"` is refused: it names system principals, which are never viewers
   * (see the `System` module).
   */
  readonly principalType?: string;
  /**
   * The resource entity type an ownership decision is made against. Defaults
   * to `"Owned"`. Only its `owner` attribute is read.
   */
  readonly ownedType?: string;
}

const axisName = (min: string | Ladder.Axis): string => (Predicate.isString(min) ? min : min.name);

/** Thrown by {@link make} for a `principalType` it refuses. */
class ReservedPrincipalTypeError extends Data.TaggedError("ReservedPrincipalTypeError")<{
  readonly message: string;
}> {}

/**
 * Build the guard kit for one viewer service and one ladder.
 *
 * @since 1.0.0
 * @category constructors
 */
export const make = <Id, User extends ViewerShape, Rung extends string>(
  options: GuardOptions<Id, User, Rung>,
): Guards<Id, User, Rung> => {
  const { ladder } = options;
  const principalType = options.principalType ?? "User";
  const ownedType = options.ownedType ?? "Owned";
  if (principalType === Entity.systemType) {
    throw new ReservedPrincipalTypeError({
      message: `Guard.make: principalType "${principalType}" is reserved for system principals; a viewer is a user`,
    });
  }
  type Min = Rung | Ladder.Axis<Rung>;

  // Scoped to the viewer's principal type, so a rung or owner grant written
  // for users can never match a system principal (`System::"<name>"`), even one
  // whose entity the resolver happens to give a `role` attribute.
  const roleAtLeast = (min: Min): ReadonlyArray<Policy.DeclarativePolicy> => [
    Policy.roleAtLeast(ladder, min, {
      id: `guard:role:${axisName(min)}`,
      principal: Policy.isType(principalType),
    }),
  ];

  const ownerOrRole = (min: Min): ReadonlyArray<Policy.DeclarativePolicy> => [
    Policy.permit({
      id: "guard:owner",
      principal: Policy.isType(principalType),
      resource: Policy.isType(ownedType),
      when: Condition.eq(Condition.principal, Condition.attr("resource", "owner")),
    }),
    Policy.roleAtLeast(ladder, min, {
      id: `guard:owner-or-role:${axisName(min)}`,
      principal: Policy.isType(principalType),
    }),
  ];

  const principalOf = (viewer: User): Entity.Entity =>
    Entity.entity(Entity.ref(principalType, viewer.id), { attributes: { role: viewer.role } });

  const decide = (
    policies: ReadonlyArray<Policy.DeclarativePolicy>,
    viewer: User,
    action: string,
    resource: Entity.Entity,
  ): boolean => {
    const principal = principalOf(viewer);
    return Policy.decidePure(
      policies,
      Policy.request({
        principal: principal.ref,
        action: Entity.ref("Action", action),
        resource: resource.ref,
      }),
      Entity.slice([principal, resource]),
    ).allowed;
  };

  const noResource = Entity.entity(Entity.ref("Guard", "none"));

  const decideRole = (viewer: User | null | undefined, min: Min): boolean =>
    viewer !== null &&
    viewer !== undefined &&
    decide(roleAtLeast(min), viewer, `role:${axisName(min)}`, noResource);

  const decideOwnerOrRole = (
    viewer: User | null | undefined,
    ownerId: string | undefined,
    min: Min,
  ): boolean => {
    if (viewer === null || viewer === undefined) return false;
    const owned = Entity.entity(
      Entity.ref(ownedType, ""),
      ownerId === undefined
        ? {}
        : { attributes: { owner: Entity.entityValue(Entity.ref(principalType, ownerId)) } },
    );
    return decide(ownerOrRole(min), viewer, `owner-or-role:${axisName(min)}`, owned);
  };

  const viewer: Effect.Effect<Option.Option<User>, never, Id> = options.viewer;

  const requireUser: Effect.Effect<User, Unauthorized, Id> = Effect.flatMap(viewer, (maybe) =>
    Option.isSome(maybe)
      ? Effect.succeed(maybe.value)
      : Effect.fail(new Unauthorized({ message: "Unauthorized" })),
  );

  const gate = (
    allowed: (user: User) => boolean,
  ): Effect.Effect<User, Unauthorized | Forbidden, Id> =>
    Effect.flatMap(requireUser, (user) =>
      allowed(user) ? Effect.succeed(user) : Effect.fail(new Forbidden({ message: "Forbidden" })),
    );

  const predicate = (allowed: (user: User) => boolean): Effect.Effect<boolean, never, Id> =>
    Effect.map(viewer, (maybe) => Option.isSome(maybe) && allowed(maybe.value));

  return {
    ladder,
    viewer,
    principal: principalOf,
    principalType,
    requireUser,
    requireRoleAtLeast: (min) => gate((user) => decideRole(user, min)),
    requireOwnerOrRole: (ownerId, min) => gate((user) => decideOwnerOrRole(user, ownerId, min)),
    isSignedIn: Effect.map(viewer, Option.isSome),
    hasRoleAtLeast: (min) => predicate((user) => decideRole(user, min)),
    isOwnerOrRole: (ownerId, min) => predicate((user) => decideOwnerOrRole(user, ownerId, min)),
    decideRole,
    decideOwnerOrRole,
    roleCapabilities: (min) => (user) => {
      const canWrite = decideRole(user, min);
      return { canEdit: canWrite, canDelete: canWrite };
    },
    ownedCapabilities: (min, ownerOf) => (resource, user) => {
      const canWrite = decideOwnerOrRole(user, ownerOf(resource), min);
      return { canEdit: canWrite, canDelete: canWrite };
    },
    policies: { roleAtLeast, ownerOrRole },
  };
};

/**
 * The system gate: the {@link Authorizer.CurrentPrincipal} when it is a system
 * principal (`System::"<name>"`, provided by `System.provide` or
 * `System.layer`) and the `Authorizer`'s policies grant it `input.action` on
 * `input.resource`. Yields the principal's `EntityRef`, since a job has no user
 * to yield.
 *
 * Fails with {@link Unauthorized} when there is no current principal or it is
 * not a system principal (a user goes through the kit's user gates), and with
 * {@link Forbidden} when no policy grants the system principal the action. The
 * decision is the `Authorizer`'s, so it runs every policy, stored ones
 * included, and is logged as `authorization.decision` with the principal's
 * name. The module docs show it composed with a user gate.
 *
 * @since 1.0.0
 * @category gates
 */
export const requireSystem = (
  input: Authorizer.AuthorizeInput,
): Effect.Effect<
  Entity.EntityRef,
  Unauthorized | Forbidden | Errors.AuthError,
  Authorizer.Authorizer
> =>
  Effect.gen(function* () {
    const current = yield* Effect.serviceOption(Authorizer.CurrentPrincipal);
    if (Option.isNone(current) || current.value.type !== Entity.systemType) {
      return yield* new Unauthorized({ message: "Unauthorized" });
    }
    const principal = current.value;
    const authorizer = yield* Authorizer.Authorizer;
    const allowed = yield* authorizer
      .check(input)
      .pipe(Authorizer.CurrentPrincipal.provide(principal));
    if (!allowed) return yield* new Forbidden({ message: "Forbidden" });
    return principal;
  });
