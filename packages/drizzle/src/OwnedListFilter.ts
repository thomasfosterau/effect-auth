/**
 * `Auth.OwnedAccess.readScope` rendered as a drizzle `WHERE` over an owned
 * table's columns. Missing `draft`, `unapproved` or `group` columns only narrow
 * it, and the follow and group sets stay subqueries ({@link isFollowerLayer},
 * {@link isMemberLayer}). It agrees row for row with `canView` and
 * `ReadScope.compile`.
 *
 * @example
 * ```ts
 * import { Effect } from "effect"
 * import { eq, sql } from "drizzle-orm"
 * import * as Drizzle from "@thomasfosterau/effect-auth-drizzle"
 *
 * const listPosts = Effect.gen(function* () {
 *   const scope = yield* owned.readScope
 *   const where = Drizzle.ownedListFilter({
 *     owner: posts.ownerId,
 *     visibility: posts.visibility,
 *     draft: posts.draft,
 *     unapproved: sql`${posts.moderation} <> 'approved'`,
 *     group: posts.groupId,
 *   })(scope)
 *   return yield* Effect.promise(() => db.select().from(posts).where(where).limit(50))
 * })
 *
 * // The follower seam, over the application's own follow table:
 * const followers = Drizzle.isFollowerLayer({
 *   isFollower: (followerId, ownerId) => … ,
 *   followingQuery: (followerId) =>
 *     db.select({ id: follows.ownerId }).from(follows).where(eq(follows.followerId, followerId)),
 * })
 *
 * // The member seam, over the application's own membership table:
 * const members = Drizzle.isMemberLayer({
 *   isMember: (accountId, groupId) => … ,
 *   groupsQuery: (accountId) =>
 *     db.select({ id: memberships.groupId }).from(memberships).where(eq(memberships.accountId, accountId)),
 * })
 * ```
 *
 * @module owned-list-filter
 */
import { and, eq, inArray, or, type SQL, type SQLWrapper } from "drizzle-orm";
import { Effect, Layer, Match } from "effect";
import * as P from "effect/Predicate";
import * as Auth from "@thomasfosterau/effect-auth";

/**
 * The columns an owned-material list is filtered on. Any column or SQL
 * expression works — a table's columns, a view's, an alias.
 *
 * @since 0.1.0
 * @category models
 */
export interface OwnedColumns {
  /** The owner's id. */
  readonly owner: SQLWrapper;
  /** The four-state visibility (`public | followers | group | private`). */
  readonly visibility: SQLWrapper;
  /** The draft flag, for a table that has one. Omit it for a table that does not. */
  readonly draft?: SQLWrapper;
  /**
   * Whether the row awaits (or failed) moderation: `true` for anything but the
   * approved state. Omit it for a table with no moderation axis.
   */
  readonly unapproved?: SQLWrapper;
  /**
   * The group a `group` row is shared with, read against the scope's group
   * set. Omit it and `group` rows list only for their owner.
   */
  readonly group?: SQLWrapper;
}

const isSqlWrapper = (value: unknown): value is SQLWrapper =>
  P.isObjectOrArray(value) && P.hasProperty(value, "getSQL") && P.isFunction(value.getSQL);

/** A follow or group set as a nestable query; one this renderer cannot nest reads as `Nobody`. */
const nested = (set: Auth.OwnedAccess.FollowingSet): SQLWrapper | undefined =>
  Match.value(set).pipe(
    Match.tag("Subquery", ({ query }) => (isSqlWrapper(query) ? query : undefined)),
    Match.orElse(() => undefined),
  );

/**
 * Render an owned-material read scope as a `WHERE` over `columns`.
 * `undefined` means no filter (the `all` scope), which is what drizzle's
 * `.where(undefined)` reads it as.
 *
 * @since 0.1.0
 * @category rendering
 */
export const ownedListFilter =
  (columns: OwnedColumns) =>
  (scope: Auth.OwnedAccess.OwnedReadScope): SQL | undefined => {
    const { owner, visibility, draft, unapproved, group } = columns;
    const published = (...clauses: ReadonlyArray<SQL>): SQL | undefined =>
      and(
        ...clauses,
        draft === undefined ? undefined : eq(draft, false),
        unapproved === undefined ? undefined : eq(unapproved, false),
      );
    const isPublic = published(eq(visibility, "public"));

    return Match.value(scope).pipe(
      Match.discriminatorsExhaustive("kind")({
        all: (): SQL | undefined => undefined,
        public: () => isPublic,
        member: ({ userId, following, groups }) => {
          const followed = nested(following);
          const memberOf = nested(groups);
          return or(
            isPublic,
            eq(owner, userId),
            followed === undefined
              ? undefined
              : published(eq(visibility, "followers"), inArray(owner, followed)),
            group === undefined || memberOf === undefined
              ? undefined
              : published(eq(visibility, "group"), inArray(group, memberOf)),
          );
        },
      }),
    );
  };

/**
 * Provide `Auth.OwnedAccess.IsFollower` over an application's own follow
 * relation: the row check, and the viewer's follow set as a drizzle query
 * nested into {@link ownedListFilter}'s `owner IN (…)`.
 *
 * @since 0.1.0
 * @category layers
 */
export const isFollowerLayer = (options: {
  readonly isFollower: (followerId: string, ownerId: string) => Effect.Effect<boolean>;
  readonly followingQuery: (followerId: string) => SQLWrapper;
}): Layer.Layer<Auth.OwnedAccess.IsFollower> =>
  Layer.succeed(Auth.OwnedAccess.IsFollower, {
    isFollower: options.isFollower,
    following: (followerId) => Auth.OwnedAccess.subquery(options.followingQuery(followerId)),
  });

/**
 * Provide `Auth.OwnedAccess.IsMember` over an application's own membership
 * relation: the row check, and the viewer's group set as a drizzle query
 * nested into {@link ownedListFilter}'s `group IN (…)`. A pending invitation
 * is not membership, so neither should count one.
 *
 * @since 0.6.0
 * @category layers
 */
export const isMemberLayer = (options: {
  readonly isMember: (accountId: string, groupId: string) => Effect.Effect<boolean>;
  readonly groupsQuery: (accountId: string) => SQLWrapper;
}): Layer.Layer<Auth.OwnedAccess.IsMember> =>
  Layer.succeed(Auth.OwnedAccess.IsMember, {
    isMember: options.isMember,
    groupsOf: (accountId) => Auth.OwnedAccess.subquery(options.groupsQuery(accountId)),
  });
