/**
 * The owned-material read scope rendered as a drizzle `WHERE`.
 *
 * `Auth.OwnedAccess.readScope` resolves, once per request, the three facts a
 * LIST of owned rows is filtered by — who the viewer is, whether they see
 * everything, and whom they follow. {@link ownedListFilter} turns those facts
 * into SQL over the columns a table (or view) actually has:
 *
 * | scope    | `WHERE`                                                                  |
 * | -------- | ------------------------------------------------------------------------ |
 * | `all`    | none (`undefined`)                                                       |
 * | `public` | `visibility = 'public'` [`AND draft = false`]                            |
 * | `member` | public-and-published, OR `owner = <viewer>`, OR `visibility = 'followers'` [`AND draft = false`] `AND owner IN (<following>)` |
 *
 * The owner's own arm never excludes drafts, so a member lists their drafts
 * alongside their published rows; every other arm does, when the table has a
 * draft column. This is the set-shaped twin of `Auth.OwnedAccess`'s per-row
 * `canView`, built from the same facts, and `OwnedListFilter.test.ts` runs
 * both over one corpus in a real Postgres and requires them to agree on every
 * row.
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
 * the renderer fails closed on a value it cannot render.
 *
 * @example
 * ```ts
 * import { Effect } from "effect"
 * import { eq } from "drizzle-orm"
 * import * as Drizzle from "@thomasfosterau/effect-auth-drizzle"
 *
 * const listPosts = Effect.gen(function* () {
 *   const scope = yield* owned.readScope
 *   const where = Drizzle.ownedListFilter({
 *     owner: posts.ownerId,
 *     visibility: posts.visibility,
 *     draft: posts.draft,
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
 * ```
 *
 * @module owned-list-filter
 */
import { and, eq, inArray, or, type SQL, type SQLWrapper } from "drizzle-orm";
import { Effect, Layer, Match, Predicate } from "effect";
import * as Auth from "@thomasfosterau/effect-auth";

/**
 * The columns an owned-material list is filtered on. Any column or SQL
 * expression works — a table's columns, a view's, an alias.
 *
 * @since 1.0.0
 * @category models
 */
export interface OwnedColumns {
  /** The owner's id. */
  readonly owner: SQLWrapper;
  /** The three-state visibility (`public | followers | private`). */
  readonly visibility: SQLWrapper;
  /** The draft flag, for a table that has one. Omit it for a table that does not. */
  readonly draft?: SQLWrapper | undefined;
}

const isSqlWrapper = (value: unknown): value is SQLWrapper =>
  Predicate.isObjectOrArray(value) &&
  Predicate.hasProperty(value, "getSQL") &&
  Predicate.isFunction(value.getSQL);

/**
 * Render an owned-material read scope as a `WHERE` over `columns`.
 * `undefined` means no filter (the `all` scope), which is what drizzle's
 * `.where(undefined)` reads it as.
 *
 * @since 1.0.0
 * @category rendering
 */
export const ownedListFilter =
  (columns: OwnedColumns) =>
  (scope: Auth.OwnedAccess.OwnedReadScope): SQL | undefined => {
    const { owner, visibility, draft } = columns;
    const published = (clause: SQL): SQL =>
      // SAFETY: `and` yields `undefined` only when every condition is; both are defined here.
      draft === undefined ? clause : (and(clause, eq(draft, false)) as SQL);
    const isPublic = published(eq(visibility, "public"));

    return Match.value(scope).pipe(
      Match.discriminatorsExhaustive("kind")({
        all: (): SQL | undefined => undefined,
        public: () => isPublic,
        member: ({ userId, following }) => {
          const own = eq(owner, userId);
          // A follow set this renderer cannot nest reads as `Nobody`.
          const followed = Match.value(following).pipe(
            Match.tag("Subquery", ({ query }) => (isSqlWrapper(query) ? query : undefined)),
            Match.orElse(() => undefined),
          );
          if (followed === undefined) {
            return or(isPublic, own);
          }
          return or(
            isPublic,
            own,
            // SAFETY: `and` yields `undefined` only when every condition is; both are defined here.
            published(and(eq(visibility, "followers"), inArray(owner, followed)) as SQL),
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
 * @since 1.0.0
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
