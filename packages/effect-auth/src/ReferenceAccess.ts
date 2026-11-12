/**
 * Reference-material read access: corpus rows with no owner, written at a
 * corpus-write rung and read along the same visibility axis as owned material
 * (`OwnedAccess.Visibility`), with no draft or moderation axis.
 *
 * | visibility         | who may view                                                       |
 * | ------------------ | ------------------------------------------------------------------ |
 * | absent (no axis)   | everyone: the view has no visibility column                        |
 * | `public`           | everyone, anonymous included                                       |
 * | `followers`        | the row's followers-of account and its followers (`IsFollower`); the `viewPrivate` axis |
 * | `group`            | the members of the row's group (`IsMember`); the `viewPrivate` axis |
 * | `private`          | the `viewPrivate` axis only                                        |
 *
 * The followers-of account is a reader, not an owner: it reads its
 * `followers` rows and nothing else, so its `private` rows stay the axis's
 * alone. A followers-of account or group that is absent or not a string names
 * nobody: the row reads as `private`, and no seam is asked about it.
 *
 * ### No axis is a property of the view
 *
 * `visibility` left out of a {@link ReferenceRow} means the view has no
 * visibility column at all, so every row is visible. The policies read that
 * as the context fact `unscoped`, not as a missing row attribute, so a
 * compiled list scope never reads a NULL `visibility` column as "no axis":
 * compile with `context: { unscoped: true }` for a view without the column
 * (the scope is then `AllowAll`) and `{ unscoped: false }` for one with it,
 * where a NULL reads as `private`. A compile that omits the fact fails closed.
 *
 * ### The same read scope
 *
 * {@link ReferenceAccess.readScope} returns `OwnedAccess.OwnedReadScope` —
 * `all`, `public` or `member { userId, following, groups }` — so one renderer
 * filters both kinds and the two readings cannot disagree. For a reference
 * view the `member` arm reads: public rows, OR `followers` rows whose
 * followers-of account is `userId` or in `following`, OR `group` rows whose
 * group is in `groups`.
 *
 * The four role axes, and the fail-closed rule for a role outside the ladder,
 * are described in the `OwnedAccess` module docs.
 *
 * @module reference-access
 */
import { Effect, Option, Predicate } from "effect";
import * as Condition from "./Condition.ts";
import * as Entity from "./Entity.ts";
import type * as Guard from "./Guard.ts";
import type * as Ladder from "./Ladder.ts";
import * as OwnedAccess from "./OwnedAccess.ts";
import * as Policy from "./Policy.ts";
import type * as ReadScope from "./ReadScope.ts";

/**
 * The facts a read of one reference row is decided from.
 *
 * @since 0.3.0
 * @category models
 */
export interface ReferenceRow {
  /** Absent: the view has no visibility axis, so the row is visible. */
  readonly visibility?: OwnedAccess.Visibility | undefined;
  /** The account whose followers (and itself) may read a `followers` row; absent or undefined: nobody. */
  readonly followersOf?: string | undefined;
  /** The group whose members may read a `group` row; absent or undefined: none. */
  readonly groupId?: string | undefined;
}

/**
 * The reference-material read access for one guard kit and one `viewPrivate`
 * axis. Build it with {@link make}.
 *
 * @since 0.3.0
 * @category models
 */
export interface ReferenceAccess<Id> {
  /** The per-row predicate. Never fails; `false` is a 404 to the caller. */
  readonly canView: (row: ReferenceRow) => Effect.Effect<boolean, never, Id>;
  /** The per-request read scope a list renders as its `WHERE`; the owned shape. */
  readonly readScope: Effect.Effect<OwnedAccess.OwnedReadScope, never, Id>;
  /**
   * The declarative read policies {@link ReferenceAccess.canView} decides,
   * each scoped to `Action::"read"`. The row is the resource (`visibility`,
   * `followersOf` and `group` attributes, each absent when the row has none);
   * `context.unscoped` says the view has no visibility axis, and
   * `context.follows` / `context.member` are the seams' answers. Their
   * principal scopes are unscoped (`any`), which never reaches a system
   * principal.
   */
  readonly policies: ReadonlyArray<Policy.DeclarativePolicy>;
  /**
   * The `ReadScope.Binding` {@link ReferenceAccess.policies} compile against:
   * `context.follows` is the set `following` over `followersOf`, and
   * `context.member` the set `groups` over `group`. Supply `unscoped` in the
   * compile request's context.
   */
  readonly binding: ReadScope.Binding;
}

/**
 * Options for {@link make}.
 *
 * @since 0.3.0
 * @category models
 */
export interface ReferenceAccessOptions<Id, User extends Guard.ViewerShape, Rung extends string> {
  readonly guards: Guard.Guards<Id, User, Rung>;
  /** The axis that sees every reference row. */
  readonly viewPrivate: NoInfer<Rung> | Ladder.Axis<NoInfer<Rung>>;
  /** The resource entity type rows are decided as. Defaults to `"Reference"`. */
  readonly referenceType?: string;
}

const anonymousPrincipal = Entity.entity(Entity.ref("Anonymous", "anonymous"));
const readAction = Entity.ref("Action", "read");

/** `resource.visibility == <value>`. */
const visibilityIs = (value: OwnedAccess.Visibility): Condition.Condition =>
  Condition.eq(Condition.attr("resource", "visibility"), Condition.lit(value));

/** `context.<fact> == true`. */
const holds = (fact: string): Condition.Condition =>
  Condition.eq(Condition.attr("context", fact), Condition.lit(true));

/** The seam questions a reference row can be decided by. */
const questionsFor = (row: ReferenceRow): OwnedAccess.RelationQuestions => {
  if (row.visibility === "followers") return { followersOf: row.followersOf };
  return row.visibility === "group" ? { groupId: row.groupId } : {};
};

/**
 * Build the reference-material read access.
 *
 * @example
 * ```ts
 * import assert from "node:assert/strict"
 * import { Context, Effect, Layer, Option } from "effect"
 * import * as Auth from "@thomasfosterau/effect-auth"
 *
 * interface AppUser { readonly id: string; readonly role: string }
 * class CurrentViewer extends Context.Service<CurrentViewer, Option.Option<AppUser>>()(
 *   "@app/CurrentViewer",
 * ) {}
 *
 * const Roles = Auth.Ladder.make(["user", "contributor", "moderator"])
 * const Axes = Roles.axes({ viewPrivate: "moderator" })
 * const guards = Auth.Guard.make({ ladder: Roles, viewer: CurrentViewer })
 * const reference = Auth.ReferenceAccess.make({ guards, viewPrivate: Axes.viewPrivate })
 *
 * // bea follows the herbarium account.
 * const Follows = Layer.succeed(Auth.OwnedAccess.IsFollower, {
 *   isFollower: (followerId, ownerId) => Effect.succeed(followerId === "bea" && ownerId === "herbarium"),
 *   following: () => Auth.OwnedAccess.nobody,
 * })
 * const as = (viewer: AppUser | null, row: Auth.ReferenceAccess.ReferenceRow) =>
 *   Effect.runSync(
 *     reference.canView(row).pipe(
 *       Effect.provide(Layer.merge(Layer.succeed(CurrentViewer, Option.fromNullishOr(viewer)), Follows)),
 *     ),
 *   )
 * const herbarium = { id: "herbarium", role: "user" }
 * const bea = { id: "bea", role: "user" }
 *
 * assert.equal(as(null, {}), true) // no visibility axis on the view
 * assert.equal(as(bea, { visibility: "followers", followersOf: "herbarium" }), true)
 * assert.equal(as(herbarium, { visibility: "followers", followersOf: "herbarium" }), true)
 * // The followers-of account is a reader, not an owner.
 * assert.equal(as(herbarium, { visibility: "private", followersOf: "herbarium" }), false)
 * assert.equal(as({ id: "mod", role: "moderator" }, { visibility: "private" }), true)
 * ```
 *
 * @since 0.3.0
 * @category constructors
 */
export const make = <Id, User extends Guard.ViewerShape, Rung extends string>(
  options: ReferenceAccessOptions<Id, User, Rung>,
): ReferenceAccess<Id> => {
  const { guards, viewPrivate } = options;
  const referenceType = options.referenceType ?? "Reference";
  const scoped = { action: Policy.eq(readAction), resource: Policy.isType(referenceType) };

  const policies: ReadonlyArray<Policy.DeclarativePolicy> = [
    Policy.permit({ id: "reference:unscoped", ...scoped, when: holds("unscoped") }),
    Policy.permit({ id: "reference:public", ...scoped, when: visibilityIs("public") }),
    Policy.roleAtLeast(guards.ladder, viewPrivate, { id: "reference:view-private", ...scoped }),
    Policy.permit({
      id: "reference:followers-of",
      ...scoped,
      when: Condition.and(
        visibilityIs("followers"),
        Condition.eq(Condition.principal, Condition.attr("resource", "followersOf")),
      ),
    }),
    Policy.permit({
      id: "reference:follower",
      ...scoped,
      when: Condition.and(
        visibilityIs("followers"),
        Condition.has("resource", "followersOf"),
        holds("follows"),
      ),
    }),
    Policy.permit({
      id: "reference:group",
      ...scoped,
      when: Condition.and(
        visibilityIs("group"),
        Condition.has("resource", "group"),
        holds("member"),
      ),
    }),
  ];

  const binding: ReadScope.Binding = {
    resourceType: referenceType,
    attributes: {
      visibility: "Text",
      followersOf: { entity: guards.principalType },
      group: "Text",
    },
    setFacts: {
      follows: { attribute: "followersOf", set: "following" },
      member: { attribute: "group", set: "groups" },
    },
  };

  const decide = (
    viewer: Option.Option<User>,
    row: ReferenceRow,
    facts: OwnedAccess.RelationFacts,
  ): boolean => {
    const principal = Option.isSome(viewer) ? guards.principal(viewer.value) : anonymousPrincipal;
    const resource = Entity.entity(Entity.ref(referenceType, ""), {
      attributes: {
        ...(row.visibility === undefined ? {} : { visibility: row.visibility }),
        // The guards' principal type, so the anonymous principal never matches it.
        ...(Predicate.isString(row.followersOf)
          ? { followersOf: Entity.entityValue(Entity.ref(guards.principalType, row.followersOf)) }
          : {}),
        ...(Predicate.isString(row.groupId) ? { group: row.groupId } : {}),
      },
    });
    return Policy.decidePure(
      policies,
      Policy.request({
        principal: principal.ref,
        action: readAction,
        resource: resource.ref,
        context: { unscoped: row.visibility === undefined, ...facts },
      }),
      Entity.slice([principal, resource]),
    ).allowed;
  };

  const canView = (row: ReferenceRow): Effect.Effect<boolean, never, Id> =>
    Effect.gen(function* () {
      const viewer = yield* guards.viewer;
      if (decide(viewer, row, { follows: false, member: false })) return true;
      if (Option.isNone(viewer)) return false;
      const facts = yield* OwnedAccess.relationFacts(viewer.value.id, questionsFor(row));
      return (facts.follows || facts.member) && decide(viewer, row, facts);
    });

  // The scope depends only on the viewer, the axis and the seams: exactly the
  // owned scope, so one renderer serves both kinds.
  const { readScope } = OwnedAccess.make({ guards, viewPrivate });

  return { canView, readScope, policies, binding };
};
