/**
 * Zero-IO guards over a resolved viewer: gates that fail with `Unauthorized` or
 * `Forbidden`, predicates that never fail, {@link requireSystem} for jobs, and
 * capability hooks for `meta.canEdit` / `canDelete`. Each decision is
 * `Policy.decidePure` over {@link Guards.policies}. Answer a `false` read
 * predicate as not found, never `Forbidden`.
 *
 * @example
 * ```ts
 * import assert from "node:assert/strict"
 * import { Context, Effect, Layer, Result } from "effect"
 * import * as Option from "effect/Option"
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
import * as Context from "effect/Context";
import * as Data from "effect/Data";
import * as Effect from "effect/Effect";
import * as Option from "effect/Option";
import * as P from "effect/Predicate";
import * as Schema from "effect/Schema";
import * as Str from "effect/String";
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
 * @since 0.1.0
 * @category errors
 */
export class Unauthorized extends Schema.TaggedError<
  Unauthorized,
  { readonly brand: unique symbol }
>()("Unauthorized", {
  message: Schema.String,
  code: Schema.optional(Schema.String),
}) {}

/**
 * 403 — there is a viewer, and the gate refuses them. Never the answer to a
 * **read** the viewer may not see: that is a 404, since a 403 confirms the row
 * exists.
 *
 * @since 0.1.0
 * @category errors
 */
export class Forbidden extends Schema.TaggedError<Forbidden, { readonly brand: unique symbol }>()(
  "Forbidden",
  {
    message: Schema.String,
    code: Schema.optional(Schema.String),
  },
) {}

// ---------------------------------------------------------------------------
// The viewer
// ---------------------------------------------------------------------------

/**
 * What the guards need of a viewer: an id and one rung. The application's own
 * user type is kept intact through every gate — `requireUser` yields `User`,
 * not this shape.
 *
 * @since 0.1.0
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
 * @since 0.1.0
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
 * @since 0.1.0
 * @category models
 */
export interface Guards<Id, User extends ViewerShape, Rung extends string> {
  /** The ladder the kit compares against. */
  readonly ladder: Ladder.Ladder<Rung>;
  /** The resolved viewer, `Option.none()` when anonymous (or its id is empty). Never fails. */
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
 * @since 0.1.0
 * @category models
 */
export interface GuardOptions<Id, User extends ViewerShape, Rung extends string> {
  readonly ladder: Ladder.Ladder<Rung>;
  /**
   * The application's viewer service: `Option<User>`, `none` when anonymous.
   * Provide it with `SessionContext.viewerLayer` /
   * `SessionContext.viewerFromSession`. A viewer whose `id` is empty is read
   * as anonymous: an empty id names no principal.
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

const axisName = (min: string | Ladder.Axis): string => (P.isString(min) ? min : min.name);

/** Thrown by {@link make} for a `principalType` it refuses. */
class ReservedPrincipalTypeError extends Data.TaggedError("ReservedPrincipalTypeError")<{
  readonly message: string;
}> {}

/**
 * Build the guard kit for one viewer service and one ladder.
 *
 * @since 0.1.0
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
      Entity.ref(ownedType, "row"),
      ownerId === undefined
        ? {}
        : { attributes: { owner: Entity.entityValue(Entity.ref(principalType, ownerId)) } },
    );
    return decide(ownerOrRole(min), viewer, `owner-or-role:${axisName(min)}`, owned);
  };

  // An empty id names no principal: such a viewer is anonymous, so no
  // gate passes for it and no owned row with an empty owner is its own.
  const viewer: Effect.Effect<Option.Option<User>, never, Id> = Effect.map(
    options.viewer,
    Option.filter((user) => Str.isNonEmpty(user.id)),
  );

  const requireUser: Effect.Effect<User, Unauthorized, Id> = Effect.flatMap(
    viewer,
    Effect.fromOption(() => new Unauthorized({ message: "Unauthorized" })),
  );

  const gate = (
    allowed: (user: User) => boolean,
  ): Effect.Effect<User, Unauthorized | Forbidden, Id> =>
    Effect.filterOrFail(requireUser, allowed, () => new Forbidden({ message: "Forbidden" }));

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
 * name. The example composes it with a user gate.
 *
 * @example A user gate or the system gate
 * ```ts
 * import assert from "node:assert/strict"
 * import { Context, Effect, Layer, Result } from "effect"
 * import * as Option from "effect/Option"
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
 * @since 0.1.0
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
