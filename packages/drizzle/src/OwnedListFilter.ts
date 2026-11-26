/**
 * The owned-material read scope rendered as a drizzle `WHERE`.
 *
 * `Auth.OwnedAccess.readScope` resolves, once per request, the facts a LIST
 * of owned rows is filtered by — who the viewer is, whether they see
 * everything, whom they follow and which groups they belong to.
 * {@link ownedListFilter} turns those facts into SQL over the columns a table
 * (or view) actually has. "Published" below is `draft = false AND
 * unapproved = false`, each conjunct present only when the table has that
 * column:
 *
 * | scope    | `WHERE`                                                                  |
 * | -------- | ------------------------------------------------------------------------ |
 * | `all`    | none (`undefined`)                                                       |
 * | `public` | `visibility = 'public'` AND published                                    |
 * | `member` | public-and-published, OR `owner = <viewer>`, OR `visibility = 'followers'` AND published `AND owner IN (<following>)`, OR `visibility = 'group'` AND published `AND group IN (<groups>)` |
 *
 * The owner's own arm never excludes drafts or unapproved rows, so a member
 * lists their pending material alongside their published rows; every other
 * arm does. This is the set-shaped twin of `Auth.OwnedAccess`'s per-row
 * `canView` and of `ReadScope.compile` over `Auth.OwnedAccess.policies` and
 * `binding`, built from the same facts, and `OwnedListFilter.test.ts` runs all
 * three over one corpus in a real Postgres and requires them to agree on every
 * row.
 *
 * ### Columns a table may not have
 *
 * - **No `group` column**: the `group` arm is left out, so a `group` row lists
 *   only for its owner (and the `all` scope). That is narrower than `canView`,
 *   never wider. A `NULL` group names no group, so its row reads as private.
 * - **No `unapproved` column**: the table has no moderation axis, and every
 *   row counts as approved. Map an application's own moderation state to a
 *   boolean expression (`state <> 'approved'` through drizzle's `sql`) rather than
 *   leave it out: anything but exactly the approved state is unapproved.
 * - `draft` and `unapproved` compare with `= false`, so a `NULL` in either
 *   reads as unpublished, as the policies' decision slice does.
 *
 * ### The follow set is a subquery, not a list
 *
 * The viewer's follow set reaches the `WHERE` as `owner IN (SELECT …)` — the
 * query value {@link isFollowerLayer}'s `followingQuery` returns — so it is
 * never materialised into literals and never capped: Postgres plans it as a
 * semi-join, and the only bound that matters is the list's own `LIMIT`. A
 * viewer who follows nobody (`Auth.OwnedAccess.nobody`, which is also what an
 * unprovided follower seam resolves to) simply loses the followers arm. A
 * follow set carrying anything but a drizzle query is treated the same way —
 * the renderer fails closed on a value it cannot render. The group set is
 * the same: `group IN (SELECT …)` from {@link isMemberLayer}'s `groupsQuery`,
 * or no group arm at all.
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
  readonly draft?: SQLWrapper | undefined;
  /**
   * Whether the row awaits (or failed) moderation: `true` for anything but the
   * approved state. Omit it for a table with no moderation axis.
   */
  readonly unapproved?: SQLWrapper | undefined;
  /**
   * The group a `group` row is shared with, read against the scope's group
   * set. Omit it and `group` rows list only for their owner.
   */
  readonly group?: SQLWrapper | undefined;
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
