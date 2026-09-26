/**
 * Owned-material read access: a three-state visibility axis, the follower
 * seam it resolves through, the per-row predicate, and the per-request read
 * scope a LIST builds its `WHERE` from.
 *
 * Multi-tenant applications keep a member's material on an `owner` column
 * with a `visibility` of `public | followers | private`, and optionally an
 * orthogonal `draft` flag:
 *
 * | visibility  | who may view                                              |
 * | ----------- | --------------------------------------------------------- |
 * | `public`    | everyone, anonymous included                              |
 * | `followers` | the owner; the owner's followers ({@link IsFollower}); the `viewPrivate` axis |
 * | `private`   | the owner; the `viewPrivate` axis                         |
 *
 * `draft: true` narrows whatever `visibility` allows down to the owner and the
 * `viewPrivate` axis — a `public` draft is exactly as hidden as a `private`
 * row. The two axes are independent conjuncts: `draft` never widens what
 * `visibility` hides.
 *
 * ### One set of facts, two shapes
 *
 * A single `get` asks {@link OwnedAccess.canView} of the row; a `list` asks
 * {@link OwnedAccess.readScope} once per request and renders it as a `WHERE`
 * (`ownedListFilter` in `@thomasfosterau/effect-auth-drizzle`). Both are built
 * from the same three facts — the owner, the visibility, the viewer's follow
 * set — so the list filter and the row predicate cannot drift; the drizzle
 * package's property test runs both over one corpus and requires them to agree
 * row for row. The row predicate is decided by the policy kernel
 * (`Policy.decidePure` over {@link OwnedAccess.policies}); the scope is that
 * policy set's set-shaped projection.
 *
 * ### Fail closed on the follower seam
 *
 * `followers` is the one visibility state that needs an external fact. It is
 * read through {@link IsFollower} with `Effect.serviceOption`, so a runtime that
 * does not provide it — a job, a test, a deployment before the social graph
 * exists — treats every non-owner as a non-follower: a `followers` row is then
 * visible to its owner and the `viewPrivate` axis only. An unprovided seam
 * narrows the scope; it never widens it. {@link isFollowerNever} makes that
 * posture explicit where a layer is wanted.
 *
 * ### A `false` is a 404
 *
 * `canView` is a predicate, not a gate: it never fails. A caller turns `false`
 * into the same not-found it returns for a missing id — never `Forbidden`,
 * which would confirm the row exists.
 *
 * @module owned-access
 */
import { Context, Effect, Layer, Option } from "effect";
import type { ServeableAxis } from "./Cacheability.ts";
import * as Condition from "./Condition.ts";
import * as Entity from "./Entity.ts";
import type * as Guard from "./Guard.ts";
import type * as Ladder from "./Ladder.ts";
import * as Policy from "./Policy.ts";

// ---------------------------------------------------------------------------
// Models
// ---------------------------------------------------------------------------

/**
 * The three visibility states of owned material.
 *
 * @since 1.0.0
 * @category models
 */
export type Visibility = "public" | "followers" | "private";

/**
 * The facts a read of one owned row is decided from.
 *
 * @since 1.0.0
 * @category models
 */
export interface OwnedRow {
  readonly ownerId: string;
  readonly visibility: Visibility;
  /** Omitted for a leaf that has no draft axis. */
  readonly draft?: boolean | undefined;
}

/**
 * The accounts a viewer follows, in whatever form the adapter that renders the
 * read scope understands.
 *
 * `Nobody` is the fail-closed answer every renderer understands. `Subquery`
 * carries an adapter's own query value — for the drizzle renderer a
 * `SQLWrapper` nested as `owner IN (…)`, so the set is never materialised and
 * never capped. The core never looks inside it; a renderer handed a query it
 * does not recognise must treat it as `Nobody`.
 *
 * @since 1.0.0
 * @category models
 */
export type FollowingSet =
  | { readonly _tag: "Nobody" }
  | { readonly _tag: "Subquery"; readonly query: unknown };

/**
 * The fail-closed follow set: matches nobody.
 *
 * @since 1.0.0
 * @category constructors
 */
export const nobody: FollowingSet = { _tag: "Nobody" };

/**
 * A follow set expressed as an adapter's query value.
 *
 * @since 1.0.0
 * @category constructors
 */
export const subquery = (query: unknown): FollowingSet => ({ _tag: "Subquery", query });

/**
 * The viewer's owned-material read scope — the set-shaped counterpart of
 * {@link OwnedAccess.canView}:
 *
 * - `all` — the viewer holds the `viewPrivate` axis: no visibility filter;
 * - `public` — anonymous: public, non-draft rows only;
 * - `member` — a signed-in viewer below the axis: public non-draft rows, OR
 *   their own rows (drafts included), OR non-draft `followers` rows whose
 *   owner is in `following`.
 *
 * @since 1.0.0
 * @category models
 */
export type OwnedReadScope =
  | { readonly kind: "all" }
  | { readonly kind: "public" }
  | { readonly kind: "member"; readonly userId: string; readonly following: FollowingSet };

/**
 * The axes a representation of an owned row must satisfy to be stored in, and
 * served from, a viewer-less cache (`Cacheability.publiclyServeable`): the
 * `owned:public` permit — the one arm of {@link OwnedAccess.canView} that
 * admits the anonymous viewer — restated over the wire attributes.
 *
 * `visibility` is **required**: an owned representation missing it is one
 * whose projection dropped the attribute deciding who may see it, and reading
 * that as public is a fail-open. `draft` is optional, since a leaf without the
 * draft axis never emits it; when present it must be exactly `false`.
 *
 * @since 1.0.0
 * @category cacheability
 */
export const serveableAxes: ReadonlyArray<ServeableAxis> = [
  { attribute: "visibility", equals: "public" },
  { attribute: "draft", equals: false, optional: true },
];

// ---------------------------------------------------------------------------
// The follower seam
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
 * @since 1.0.0
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
 * @since 1.0.0
 * @category layers
 */
export const isFollowerNever: Layer.Layer<IsFollower> = Layer.succeed(IsFollower, {
  isFollower: () => Effect.succeed(false),
  following: () => nobody,
});

// ---------------------------------------------------------------------------
// Access
// ---------------------------------------------------------------------------

/**
 * The owned-material read access for one guard kit and one `viewPrivate` axis.
 * Build it with {@link make}.
 *
 * @since 1.0.0
 * @category models
 */
export interface OwnedAccess<Id> {
  /** The per-row predicate. Never fails; `false` is a 404 to the caller. */
  readonly canView: (row: OwnedRow) => Effect.Effect<boolean, never, Id>;
  /** The per-request read scope a list renders as its `WHERE`. */
  readonly readScope: Effect.Effect<OwnedReadScope, never, Id>;
  /**
   * The declarative policies {@link OwnedAccess.canView} decides. The row is
   * the resource (`owner`, `visibility`, `draft` attributes); the follow fact
   * is `context.follows`.
   */
  readonly policies: ReadonlyArray<Policy.DeclarativePolicy>;
}

/**
 * Options for {@link make}.
 *
 * @since 1.0.0
 * @category models
 */
export interface OwnedAccessOptions<Id, User extends Guard.ViewerShape, Rung extends string> {
  readonly guards: Guard.Guards<Id, User, Rung>;
  /** The axis that sees other members' `private` and `followers` material, and drafts. */
  readonly viewPrivate: NoInfer<Rung> | Ladder.Axis<NoInfer<Rung>>;
  /** The resource entity type rows are decided as. Defaults to `"Owned"`. */
  readonly ownedType?: string;
}

const anonymousPrincipal = Entity.entity(Entity.ref("Anonymous", "anonymous"));

/**
 * Build the owned-material read access.
 *
 * @since 1.0.0
 * @category constructors
 */
export const make = <Id, User extends Guard.ViewerShape, Rung extends string>(
  options: OwnedAccessOptions<Id, User, Rung>,
): OwnedAccess<Id> => {
  const { guards, viewPrivate } = options;
  const ownedType = options.ownedType ?? "Owned";
  const resourceScope = Policy.isType(ownedType);
  const attr = (name: string) => Condition.attr("resource", name);
  const notDraft = Condition.eq(attr("draft"), Condition.lit(false));

  const policies: ReadonlyArray<Policy.DeclarativePolicy> = [
    Policy.permit({
      id: "owned:public",
      resource: resourceScope,
      when: Condition.and(Condition.eq(attr("visibility"), Condition.lit("public")), notDraft),
    }),
    Policy.permit({
      id: "owned:owner",
      resource: resourceScope,
      when: Condition.eq(Condition.principal, attr("owner")),
    }),
    Policy.roleAtLeast(guards.ladder, viewPrivate, {
      id: "owned:view-private",
      resource: resourceScope,
    }),
    Policy.permit({
      id: "owned:follower",
      resource: resourceScope,
      when: Condition.and(
        Condition.eq(attr("visibility"), Condition.lit("followers")),
        notDraft,
        Condition.eq(Condition.attr("context", "follows"), Condition.lit(true)),
      ),
    }),
  ];

  const decide = (viewer: Option.Option<User>, row: OwnedRow, follows: boolean): boolean => {
    const principal = Option.isSome(viewer) ? guards.principal(viewer.value) : anonymousPrincipal;
    const resource = Entity.entity(Entity.ref(ownedType, ""), {
      attributes: {
        // Always the guards' principal type — never the anonymous principal's,
        // which could otherwise equal a row owned by an id that happens to
        // match the anonymous sentinel.
        owner: Entity.entityValue(Entity.ref(guards.principalType, row.ownerId)),
        visibility: row.visibility,
        draft: row.draft === true,
      },
    });
    return Policy.decidePure(
      policies,
      Policy.request({
        principal: principal.ref,
        action: Entity.ref("Action", "read"),
        resource: resource.ref,
        context: { follows },
      }),
      Entity.slice([principal, resource]),
    ).allowed;
  };

  const canView = (row: OwnedRow): Effect.Effect<boolean, never, Id> =>
    Effect.gen(function* () {
      const viewer = yield* guards.viewer;
      if (decide(viewer, row, false)) return true;
      // Only the follower permit can still change the answer, and only for a
      // signed-in viewer on a published `followers` row: ask the seam then,
      // and not before.
      if (Option.isNone(viewer) || row.visibility !== "followers" || row.draft === true) {
        return false;
      }
      const seam = yield* Effect.serviceOption(IsFollower);
      if (Option.isNone(seam)) return false;
      const follows = yield* seam.value.isFollower(viewer.value.id, row.ownerId);
      return follows && decide(viewer, row, true);
    });

  const readScope: Effect.Effect<OwnedReadScope, never, Id> = Effect.gen(function* () {
    const viewer = yield* guards.viewer;
    if (Option.isNone(viewer)) return { kind: "public" } as const;
    if (guards.decideRole(viewer.value, viewPrivate)) return { kind: "all" } as const;
    const seam = yield* Effect.serviceOption(IsFollower);
    return {
      kind: "member",
      userId: viewer.value.id,
      following: Option.isNone(seam) ? nobody : seam.value.following(viewer.value.id),
    } as const;
  });

  return { canView, readScope, policies };
};
