/**
 * Owned-material read access: a four-state visibility axis, the two
 * publication axes that narrow it (draft and moderation), the follower and
 * member seams it resolves through, the per-row predicate, and the per-request
 * read scope a LIST builds its `WHERE` from.
 *
 * Multi-tenant applications keep a member's material on an `owner` column
 * with a `visibility` of `public | followers | group | private`, an optional
 * `group` column naming the group a `group` row is shared with, and
 * optionally two orthogonal publication flags, `draft` and `unapproved`:
 *
 * | visibility  | who may view                                              |
 * | ----------- | --------------------------------------------------------- |
 * | `public`    | everyone, anonymous included                              |
 * | `followers` | the owner; the owner's followers ({@link IsFollower}); the `viewPrivate` axis |
 * | `group`     | the owner; the members of the row's group ({@link IsMember}); the `viewPrivate` axis |
 * | `private`   | the owner; the `viewPrivate` axis                         |
 *
 * `draft: true` narrows whatever `visibility` allows down to the owner and the
 * `viewPrivate` axis — a `public` draft is exactly as hidden as a `private`
 * row. `unapproved: true` (a moderated row whose state is anything but
 * approved: pending, rejected, a state added later) narrows it in exactly the
 * same way. The axes are independent conjuncts: neither publication flag ever
 * widens what `visibility` hides, and a row is **published** only when it is
 * neither a draft nor unapproved. The application maps its own moderation
 * column to the boolean (anything but exactly its approved state is `true`),
 * so the core carries no moderation vocabulary.
 *
 * ### No owner, no group
 *
 * A row whose owner column holds no string (SQL `NULL`, an absent key) has
 * **no owner**: pass `ownerId: undefined`. No viewer matches the owner arm —
 * the decision slice carries no `owner` attribute at all, never an empty or
 * sentinel id that could equal the anonymous principal — and the follower seam
 * is never asked about it. It is visible only when `public` and published, or
 * to the `viewPrivate` axis. Never coerce a missing owner with `String(value)`.
 *
 * A `group` row whose group column holds no string names no group and reads
 * as `private`: its owner and the `viewPrivate` axis only, and the member seam
 * is never asked. That is how a deleted group's rows become private to their
 * owners.
 *
 * ### One set of facts, two shapes
 *
 * A single `get` asks {@link OwnedAccess.canView} of the row; a `list` asks
 * {@link OwnedAccess.readScope} once per request and renders it as a `WHERE`
 * (`ownedListFilter` in `@thomasfosterau/effect-auth-drizzle`). Both are built
 * from the same facts — the owner, the visibility, the publication flags, the
 * group, the viewer's follow and group sets — so the list filter and the row
 * predicate cannot drift. The row predicate is decided by the policy kernel
 * (`Policy.decidePure` over {@link OwnedAccess.policies}); the scope is that
 * policy set's set-shaped projection, and `ReadScope.compile` over the same
 * policies and {@link OwnedAccess.binding} yields the same rows.
 *
 * ### Fail closed on the seams
 *
 * `followers` and `group` are the two visibility states that need an external
 * fact. They are read through {@link IsFollower} and {@link IsMember} with
 * `Effect.serviceOption`, so a runtime that does not provide one — a job, a
 * test, a deployment before the social graph exists — treats every non-owner
 * as a non-follower (or a non-member): such a row is then visible to its owner
 * and the `viewPrivate` axis only. An unprovided seam narrows the scope; it
 * never widens it. {@link isFollowerNever} and {@link isMemberNever} make that
 * posture explicit where a layer is wanted. A seam is asked only for a
 * signed-in viewer on a published row of its visibility whose owner (or
 * group) is a string.
 *
 * ### The four role axes
 *
 * A content application usually asks four rung questions of a signed-in
 * account: may it read other members' private material, see soft-deleted
 * rows, write someone else's owned row (moderate), and write reference data.
 * They need no API beyond the ladder and the guard kit: declare them as axes
 * once and hand each to the gate or predicate that asks it.
 *
 * ```ts
 * import assert from "node:assert/strict"
 * import { Context } from "effect"
 * import * as Option from "effect/Option"
 * import * as Auth from "@thomasfosterau/effect-auth"
 *
 * interface AppUser { readonly id: string; readonly role: string }
 * class CurrentViewer extends Context.Service<CurrentViewer, Option.Option<AppUser>>()(
 *   "@app/CurrentViewer",
 * ) {}
 *
 * const Roles = Auth.Ladder.make(["user", "contributor", "moderator", "admin"])
 * const Axes = Roles.axes({
 *   viewPrivate: "moderator", // OwnedAccess.make / ReferenceAccess.make
 *   viewDeleted: "moderator", // Cacheability.shouldIncludeDeleted
 *   moderate: "moderator", // guards.requireOwnerOrRole(ownerId, Axes.moderate)
 *   writeCorpus: "contributor", // guards.requireRoleAtLeast(Axes.writeCorpus)
 * })
 * const guards = Auth.Guard.make({ ladder: Roles, viewer: CurrentViewer })
 *
 * assert.equal(guards.decideRole({ id: "c", role: "contributor" }, Axes.writeCorpus), true)
 * assert.equal(guards.decideRole({ id: "c", role: "contributor" }, Axes.moderate), false)
 * // A role outside the ladder holds no axis at all.
 * for (const axis of [Axes.viewPrivate, Axes.viewDeleted, Axes.moderate, Axes.writeCorpus]) {
 *   assert.equal(guards.decideRole({ id: "x", role: "superadmin" }, axis), false)
 * }
 * ```
 *
 * Every one fails closed on a role outside the ladder: `guards.decideRole`
 * answers `false` for it at every axis, so an unknown or retired role reads as
 * an ordinary account, never as a privileged one.
 *
 * ### A `false` is a 404
 *
 * `canView` is a predicate, not a gate: it never fails. A caller turns `false`
 * into the same not-found it returns for a missing id — never `Forbidden`,
 * which would confirm the row exists.
 *
 * @module owned-access
 */
import { Context, Effect, Layer } from "effect";
import * as Option from "effect/Option";
import * as P from "effect/Predicate";
import type { ServeableAxis } from "./Cacheability.ts";
import * as Condition from "./Condition.ts";
import * as Entity from "./Entity.ts";
import type * as Guard from "./Guard.ts";
import type * as Ladder from "./Ladder.ts";
import * as Policy from "./Policy.ts";
import type * as ReadScope from "./ReadScope.ts";

// ---------------------------------------------------------------------------
// Models
// ---------------------------------------------------------------------------

/**
 * The four visibility states of owned (and reference) material.
 *
 * @since 0.1.0
 * @category models
 */
export type Visibility = "public" | "followers" | "group" | "private";

/**
 * The facts a read of one owned row is decided from.
 *
 * @since 0.1.0
 * @category models
 */
export interface OwnedRow {
  /**
   * The owner's id; `undefined` when the row has no owner (see the module
   * docs): no viewer is its owner, and no seam is asked about it.
   */
  readonly ownerId: string | undefined;
  readonly visibility: Visibility;
  /** Omitted for a leaf that has no draft axis. */
  readonly draft?: boolean | undefined;
  /**
   * `true` for a moderated row whose state is anything but approved; it reads
   * exactly as `draft: true`. Omitted (or `false`) for a leaf that has no
   * moderation axis, or an approved row.
   */
  readonly unapproved?: boolean | undefined;
  /** The group a `group` row is shared with; omitted or `undefined`: none, so the row reads as `private`. */
  readonly groupId?: string | undefined;
}

/**
 * The accounts a viewer follows (or the groups they belong to), in whatever
 * form the adapter that renders the read scope understands.
 *
 * `Nobody` is the fail-closed answer every renderer understands. `Subquery`
 * carries an adapter's own query value — for the drizzle renderer a
 * `SQLWrapper` nested as `owner IN (…)`, so the set is never materialised and
 * never capped. The core never looks inside it; a renderer handed a query it
 * does not recognise must treat it as `Nobody`.
 *
 * @since 0.1.0
 * @category models
 */
export type FollowingSet =
  | { readonly _tag: "Nobody" }
  | { readonly _tag: "Subquery"; readonly query: unknown };

/**
 * The fail-closed follow (or group) set: matches nobody.
 *
 * @since 0.1.0
 * @category constructors
 */
export const nobody: FollowingSet = { _tag: "Nobody" };

/**
 * A follow (or group) set expressed as an adapter's query value.
 *
 * @since 0.1.0
 * @category constructors
 */
export const subquery = (query: unknown): FollowingSet => ({ _tag: "Subquery", query });

/**
 * The viewer's read scope — the set-shaped counterpart of
 * {@link OwnedAccess.canView} (and of `ReferenceAccess.canView`, which returns
 * the same shape):
 *
 * - `all` — the viewer holds the `viewPrivate` axis: no visibility filter;
 * - `public` — anonymous: public, published rows only;
 * - `member` — a signed-in viewer below the axis. For owned rows: public
 *   published rows, OR their own rows (drafts and unapproved rows included),
 *   OR published `followers` rows whose owner is in `following`, OR published
 *   `group` rows whose group is in `groups`. For reference rows: public rows,
 *   OR `followers` rows whose followers-of account is `userId` or in
 *   `following`, OR `group` rows whose group is in `groups`.
 *
 * `following` and `groups` are {@link nobody} when {@link IsFollower} or
 * {@link IsMember} is not provided.
 *
 * @since 0.1.0
 * @category models
 */
export type OwnedReadScope =
  | { readonly kind: "all" }
  | { readonly kind: "public" }
  | {
      readonly kind: "member";
      readonly userId: string;
      readonly following: FollowingSet;
      readonly groups: FollowingSet;
    };

/**
 * The axes a representation of an owned row must satisfy to be stored in, and
 * served from, a viewer-less cache (`Cacheability.publiclyServeable`): the
 * `owned:public` permit — the one arm of {@link OwnedAccess.canView} that
 * admits the anonymous viewer — restated over the wire attributes.
 *
 * `visibility` is **required**: an owned representation missing it is one
 * whose projection dropped the attribute deciding who may see it, and reading
 * that as public is a fail-open. `draft` and `unapproved` are optional, since
 * a leaf without the axis never emits them; when present each must be exactly
 * `false`. `moderationState` is optional too, and when present must be exactly
 * `"approved"` (a wire representation usually carries the state rather than
 * the boolean). `deletedAt` must be absent: a tombstone, `null` included, is
 * never served from a public cache. A `group` row is refused by the
 * `visibility` axis. A publish stamp is time-dependent and stays the
 * application's check.
 *
 * Every axis added since 0.2.0 is optional or an absence check, so a
 * representation that carries none of them is decided as before.
 *
 * @since 0.1.0
 * @category cacheability
 */
export const serveableAxes: ReadonlyArray<ServeableAxis> = [
  { attribute: "visibility", equals: "public" },
  { attribute: "draft", equals: false, optional: true },
  { attribute: "unapproved", equals: false, optional: true },
  { attribute: "moderationState", equals: "approved", optional: true },
  { attribute: "deletedAt", absent: true },
];

// ---------------------------------------------------------------------------
// The follower and member seams
// ---------------------------------------------------------------------------

/**
 * Whether one account follows another — the `followers` state's one external
 * fact — in both of the shapes a read needs: a row check, and the viewer's
 * follow set for a list.
 *
 * The two live on one service so they cannot be provided separately: a runtime
 * that can answer one can answer the other, and a runtime that provides
 * neither fails closed on both.
 *
 * @since 0.1.0
 * @category services
 */
export class IsFollower extends Context.Service<
  IsFollower,
  {
    readonly isFollower: (followerId: string, ownerId: string) => Effect.Effect<boolean>;
    readonly following: (followerId: string) => FollowingSet;
  }
>()("@effect-auth/IsFollower") {}

/**
 * The fail-closed follower seam: nobody follows anybody. Layer it wherever the
 * absence should be explicit — a queue consumer, a test — so a job never
 * accidentally reads as a follower.
 *
 * @since 0.1.0
 * @category layers
 */
export const isFollowerNever: Layer.Layer<IsFollower> = Layer.succeed(IsFollower, {
  isFollower: () => Effect.succeed(false),
  following: () => nobody,
});

/**
 * Whether an account is a member of a group — the `group` state's one
 * external fact — as a row check and as the viewer's group set for a list
 * (the set a list filter's `group IN (…)` reads). A pending invitation is not
 * membership.
 *
 * Like {@link IsFollower}, both shapes live on one service, and a runtime that
 * provides neither fails closed on both.
 *
 * @since 0.3.0
 * @category services
 */
export class IsMember extends Context.Service<
  IsMember,
  {
    readonly isMember: (accountId: string, groupId: string) => Effect.Effect<boolean>;
    readonly groupsOf: (accountId: string) => FollowingSet;
  }
>()("@effect-auth/IsMember") {}

/**
 * The fail-closed member seam: nobody belongs to any group.
 *
 * @since 0.3.0
 * @category layers
 */
export const isMemberNever: Layer.Layer<IsMember> = Layer.succeed(IsMember, {
  isMember: () => Effect.succeed(false),
  groupsOf: () => nobody,
});

/**
 * The relationship questions one read may ask of the seams: whether the
 * viewer follows `followersOf`, and whether they belong to `groupId`. A
 * question whose subject is not a string is never asked.
 *
 * @since 0.3.0
 * @category models
 */
export interface RelationQuestions {
  readonly followersOf?: string | undefined;
  readonly groupId?: string | undefined;
}

/**
 * The seams' answers to {@link RelationQuestions}, as the policies read them:
 * `context.follows` and `context.member`.
 *
 * @since 0.3.0
 * @category models
 */
export interface RelationFacts {
  readonly follows: boolean;
  readonly member: boolean;
}

const noRelations: RelationFacts = { follows: false, member: false };

/** Ask one seam, if it is provided and the subject is a string; `false` otherwise. */
const ask = <I, S>(
  key: Context.Key<I, S>,
  subject: string | undefined,
  question: (seam: S, subject: string) => Effect.Effect<boolean>,
): Effect.Effect<boolean> =>
  P.isString(subject)
    ? Effect.flatMap(Effect.serviceOption(key), (seam) =>
        Option.isSome(seam) ? question(seam.value, subject) : Effect.succeed(false),
      )
    : Effect.succeed(false);

/**
 * Ask {@link IsFollower} and {@link IsMember} about `accountId`, failing
 * closed: an unprovided seam answers `false`, and a question whose subject is
 * absent or not a string is never put to the seam at all.
 *
 * @since 0.3.0
 * @category seams
 */
export const relationFacts = (
  accountId: string,
  questions: RelationQuestions,
): Effect.Effect<RelationFacts> =>
  Effect.all(
    {
      follows: ask(IsFollower, questions.followersOf, (seam, ownerId) =>
        seam.isFollower(accountId, ownerId),
      ),
      member: ask(IsMember, questions.groupId, (seam, groupId) =>
        seam.isMember(accountId, groupId),
      ),
    },
    // The two questions are independent; ask them one after the other.
    { concurrency: 1 },
  );

// ---------------------------------------------------------------------------
// Access
// ---------------------------------------------------------------------------

/**
 * The owned-material read access for one guard kit and one `viewPrivate` axis.
 * Build it with {@link make}.
 *
 * @since 0.1.0
 * @category models
 */
export interface OwnedAccess<Id> {
  /** The per-row predicate. Never fails; `false` is a 404 to the caller. */
  readonly canView: (row: OwnedRow) => Effect.Effect<boolean, never, Id>;
  /** The per-request read scope a list renders as its `WHERE`. */
  readonly readScope: Effect.Effect<OwnedReadScope, never, Id>;
  /**
   * The declarative policies {@link OwnedAccess.canView} decides, and read
   * policies only: each permit's action scope is `Action::"read"`, so under
   * these policies alone an update or delete of a row is denied, whoever asks.
   * The row is the resource (`owner`, `visibility`, `draft`, `unapproved` and
   * `group` attributes; `owner` and `group` are absent when the row has none,
   * and `draft` and `unapproved` must be present booleans, as a NULL in either
   * reads as unpublished); the seams' answers are `context.follows` and
   * `context.member`. Their principal scopes are unscoped (`any`), which the
   * kernel never lets reach a system principal (`System::"<name>"`), so
   * handing them to an `Authorizer` grants a job nothing.
   */
  readonly policies: ReadonlyArray<Policy.DeclarativePolicy>;
  /**
   * The `ReadScope.Binding` {@link OwnedAccess.policies} compile against: the
   * five row attributes, with `context.follows` as the set `following` over
   * `owner` and `context.member` as the set `groups` over `group`.
   */
  readonly binding: ReadScope.Binding;
}

/**
 * Options for {@link make}.
 *
 * @since 0.1.0
 * @category models
 */
export interface OwnedAccessOptions<Id, User extends Guard.ViewerShape, Rung extends string> {
  readonly guards: Guard.Guards<Id, User, Rung>;
  /** The axis that sees other members' `private`, `followers` and `group` material, drafts and unapproved rows. */
  readonly viewPrivate: NoInfer<Rung> | Ladder.Axis<NoInfer<Rung>>;
  /** The resource entity type rows are decided as. Defaults to `"Owned"`. */
  readonly ownedType?: string;
}

const anonymousPrincipal = Entity.entity(Entity.ref("Anonymous", "anonymous"));

/**
 * The one action the owned-material policies decide: `Action::"read"`. Every
 * `owned:*` permit is scoped to it, so the policy set answers only "may this
 * viewer read this row", never "may they update or delete it".
 */
const readAction = Entity.ref("Action", "read");
const readActionScope = Policy.eq(readAction);

/** `resource.<name> == <value>`. */
const resourceIs = (name: string, value: Entity.AttributeValue): Condition.Condition =>
  Condition.eq(Condition.attr("resource", name), Condition.lit(value));

/** `context.<fact> == true`. */
const contextHolds = (fact: string): Condition.Condition =>
  Condition.eq(Condition.attr("context", fact), Condition.lit(true));

/** The seam questions an owned row can still be decided by: only published followers and group rows ask. */
const questionsFor = (row: OwnedRow): RelationQuestions => {
  if (row.draft === true || row.unapproved === true) return {};
  if (row.visibility === "followers") return { followersOf: row.ownerId };
  return row.visibility === "group" ? { groupId: row.groupId } : {};
};

/**
 * Build the owned-material read access.
 *
 * @example
 * ```ts
 * import assert from "node:assert/strict"
 * import { Context, Effect, Layer } from "effect"
 * import * as Option from "effect/Option"
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
 * const owned = Auth.OwnedAccess.make({ guards, viewPrivate: Axes.viewPrivate })
 *
 * // bea belongs to the garden club; nobody follows anybody.
 * const Members = Layer.succeed(Auth.OwnedAccess.IsMember, {
 *   isMember: (accountId, groupId) => Effect.succeed(accountId === "bea" && groupId === "club"),
 *   groupsOf: () => Auth.OwnedAccess.nobody,
 * })
 * const as = (viewer: AppUser | null, row: Auth.OwnedAccess.OwnedRow) =>
 *   Effect.runSync(
 *     owned.canView(row).pipe(
 *       Effect.provide(Layer.merge(Layer.succeed(CurrentViewer, Option.fromNullishOr(viewer)), Members)),
 *     ),
 *   )
 * const ada = { id: "ada", role: "user" }
 * const bea = { id: "bea", role: "user" }
 *
 * const shared = { ownerId: "ada", visibility: "group", groupId: "club" } as const
 * assert.equal(as(bea, shared), true)
 * // Pending moderation hides it from the group, not from its owner.
 * assert.equal(as(bea, { ...shared, unapproved: true }), false)
 * assert.equal(as(ada, { ...shared, unapproved: true }), true)
 * // Its group was deleted: the row reads as private.
 * assert.equal(as(bea, { ...shared, groupId: undefined }), false)
 * // A row with no owner is nobody's, not even anonymous's.
 * assert.equal(as(null, { ownerId: undefined, visibility: "private" }), false)
 * assert.equal(as(null, { ownerId: undefined, visibility: "public" }), true)
 * ```
 *
 * @since 0.1.0
 * @category constructors
 */
export const make = <Id, User extends Guard.ViewerShape, Rung extends string>(
  options: OwnedAccessOptions<Id, User, Rung>,
): OwnedAccess<Id> => {
  const { guards, viewPrivate } = options;
  const ownedType = options.ownedType ?? "Owned";
  const resourceScope = Policy.isType(ownedType);
  // Published: neither a draft nor unapproved. A NULL in either errors, so the
  // permits that require it fail closed.
  const published = [resourceIs("draft", false), resourceIs("unapproved", false)] as const;

  const policies: ReadonlyArray<Policy.DeclarativePolicy> = [
    Policy.permit({
      id: "owned:public",
      action: readActionScope,
      resource: resourceScope,
      when: Condition.and(resourceIs("visibility", "public"), ...published),
    }),
    Policy.permit({
      id: "owned:owner",
      action: readActionScope,
      resource: resourceScope,
      when: Condition.eq(Condition.principal, Condition.attr("resource", "owner")),
    }),
    Policy.roleAtLeast(guards.ladder, viewPrivate, {
      id: "owned:view-private",
      action: readActionScope,
      resource: resourceScope,
    }),
    Policy.permit({
      id: "owned:follower",
      action: readActionScope,
      resource: resourceScope,
      when: Condition.and(
        resourceIs("visibility", "followers"),
        ...published,
        Condition.has("resource", "owner"),
        contextHolds("follows"),
      ),
    }),
    Policy.permit({
      id: "owned:group",
      action: readActionScope,
      resource: resourceScope,
      when: Condition.and(
        resourceIs("visibility", "group"),
        ...published,
        Condition.has("resource", "group"),
        contextHolds("member"),
      ),
    }),
  ];

  const binding: ReadScope.Binding = {
    resourceType: ownedType,
    attributes: {
      owner: { entity: guards.principalType },
      visibility: "Text",
      draft: "Boolean",
      unapproved: "Boolean",
      group: "Text",
    },
    setFacts: {
      follows: { attribute: "owner", set: "following" },
      member: { attribute: "group", set: "groups" },
    },
  };

  const decide = (viewer: Option.Option<User>, row: OwnedRow, facts: RelationFacts): boolean => {
    const principal = Option.isSome(viewer) ? guards.principal(viewer.value) : anonymousPrincipal;
    const resource = Entity.entity(Entity.ref(ownedType, "row"), {
      attributes: {
        // Always the guards' principal type — never the anonymous principal's,
        // which could otherwise equal a row owned by an id that happens to
        // match the anonymous sentinel. No owner is no attribute, never an
        // empty or sentinel id.
        ...(P.isString(row.ownerId)
          ? { owner: Entity.entityValue(Entity.ref(guards.principalType, row.ownerId)) }
          : {}),
        visibility: row.visibility,
        draft: row.draft === true,
        unapproved: row.unapproved === true,
        ...(P.isString(row.groupId) ? { group: row.groupId } : {}),
      },
    });
    return Policy.decidePure(
      policies,
      Policy.request({
        principal: principal.ref,
        action: readAction,
        resource: resource.ref,
        context: { follows: facts.follows, member: facts.member },
      }),
      Entity.slice([principal, resource]),
    ).allowed;
  };

  const canView = (row: OwnedRow): Effect.Effect<boolean, never, Id> =>
    Effect.gen(function* () {
      const viewer = yield* guards.viewer;
      if (decide(viewer, row, noRelations)) return true;
      // Only the follower and group permits can still change the answer, and
      // only for a signed-in viewer: ask the seams then, and not before.
      if (Option.isNone(viewer)) return false;
      const facts = yield* relationFacts(viewer.value.id, questionsFor(row));
      return (facts.follows || facts.member) && decide(viewer, row, facts);
    });

  const readScope: Effect.Effect<OwnedReadScope, never, Id> = Effect.flatMap(
    guards.viewer,
    (viewer): Effect.Effect<OwnedReadScope> => {
      if (Option.isNone(viewer)) return Effect.succeed({ kind: "public" });
      if (guards.decideRole(viewer.value, viewPrivate)) return Effect.succeed({ kind: "all" });
      const userId = viewer.value.id;
      return Effect.map(
        Effect.all(
          {
            follower: Effect.serviceOption(IsFollower),
            member: Effect.serviceOption(IsMember),
          },
          { concurrency: 1 },
        ),
        ({ follower, member }) => ({
          kind: "member",
          userId,
          following: Option.isNone(follower) ? nobody : follower.value.following(userId),
          groups: Option.isNone(member) ? nobody : member.value.groupsOf(userId),
        }),
      );
    },
  );

  return { canView, readScope, policies, binding };
};
