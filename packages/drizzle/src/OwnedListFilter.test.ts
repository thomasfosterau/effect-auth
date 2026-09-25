/**
 * `ownedListFilter` (#190, #221 (d)) against a real PostgreSQL engine (PGlite).
 *
 * The property the applications engineered for and this renderer exists to
 * keep: **the list filter and the single-row predicate cannot disagree.** Every
 * viewer lists a corpus that spans every owner × visibility × draft
 * combination through the rendered `WHERE`, and the ids that come back must be
 * exactly the rows `Auth.OwnedAccess.canView` admits — with the follower seam
 * backed by the same database, absent, and explicitly `isFollowerNever`.
 *
 * Ported in spirit from gardeneria `apps/api/tests/integration/
 * owned-target-visibility.test.ts` and `comment-target-visibility-flip.test.ts`
 * (the row-predicate / list-filter pair must answer the same question, and a
 * gate that hides everything is not a fix — so the positive cases are asserted
 * as hard as the negative ones), and website `apps/api/tests/
 * list-visibility-filters.test.ts` (the rendered SQL is pinned as text).
 */
import { PGlite } from "@electric-sql/pglite";
import { eq } from "drizzle-orm";
import { boolean, pgTable, text } from "drizzle-orm/pg-core";
import { drizzle, type PgliteDatabase } from "drizzle-orm/pglite";
import { PgDialect } from "drizzle-orm/pg-core";
import { Context, Effect, Option } from "effect";
import { afterAll, beforeAll, describe, expect, it } from "vite-plus/test";
import * as Auth from "@thomasfosterau/effect-auth";
import { isFollowerLayer, ownedListFilter } from "./OwnedListFilter.ts";

const posts = pgTable("posts", {
  id: text("id").primaryKey(),
  ownerId: text("owner_id").notNull(),
  visibility: text("visibility").notNull(),
  draft: boolean("draft").notNull(),
});
const gardens = pgTable("gardens", {
  id: text("id").primaryKey(),
  ownerId: text("owner_id").notNull(),
  visibility: text("visibility").notNull(),
});
const follows = pgTable("follows", {
  followerId: text("follower_id").notNull(),
  ownerId: text("owner_id").notNull(),
});

interface AppUser {
  readonly id: string;
  readonly role: string;
}
class CurrentViewer extends Context.Service<CurrentViewer, Option.Option<AppUser>>()(
  "@test/OwnedListFilter/CurrentViewer",
) {}

const Roles = Auth.Ladder.make(["user", "contributor", "moderator", "admin"]);
const Axes = Roles.axes({ viewPrivate: "moderator" });
const guards = Auth.Guard.make({ ladder: Roles, viewer: CurrentViewer });
const owned = Auth.OwnedAccess.make({ guards, viewPrivate: Axes.viewPrivate });

const OWNERS = ["alice", "bob", "carol"] as const;
const VISIBILITIES = ["public", "followers", "private"] as const;
// bob and dave follow alice; alice follows carol.
const FOLLOWS = [
  ["bob", "alice"],
  ["dave", "alice"],
  ["alice", "carol"],
] as const;

const VIEWERS: ReadonlyArray<AppUser | null> = [
  null,
  { id: "alice", role: "user" },
  { id: "bob", role: "user" },
  { id: "carol", role: "contributor" },
  { id: "dave", role: "user" },
  { id: "erin", role: "user" },
  { id: "mod", role: "moderator" },
  { id: "root", role: "admin" },
  { id: "odd", role: "superadmin" },
];

let client: PGlite;
let db: PgliteDatabase;

beforeAll(async () => {
  client = await PGlite.create();
  await client.exec(`
    create table posts (id text primary key, owner_id text not null, visibility text not null, draft boolean not null);
    create table gardens (id text primary key, owner_id text not null, visibility text not null);
    create table follows (follower_id text not null, owner_id text not null);
  `);
  db = drizzle(client);
  const postRows = OWNERS.flatMap((ownerId) =>
    VISIBILITIES.flatMap((visibility) =>
      [false, true].map((draft) => ({
        id: `${ownerId}:${visibility}:${draft ? "draft" : "published"}`,
        ownerId,
        visibility,
        draft,
      })),
    ),
  );
  await db.insert(posts).values(postRows);
  await db
    .insert(gardens)
    .values(
      OWNERS.flatMap((ownerId) =>
        VISIBILITIES.map((visibility) => ({ id: `${ownerId}:${visibility}`, ownerId, visibility })),
      ),
    );
  await db
    .insert(follows)
    .values(FOLLOWS.map(([followerId, ownerId]) => ({ followerId, ownerId })));
});

afterAll(async () => {
  await client.close();
});

const databaseFollowers = () =>
  isFollowerLayer({
    isFollower: (followerId, ownerId) =>
      Effect.promise(() =>
        db
          .select({ ownerId: follows.ownerId })
          .from(follows)
          .where(eq(follows.followerId, followerId)),
      ).pipe(Effect.map((rows) => rows.some((row) => row.ownerId === ownerId))),
    followingQuery: (followerId) =>
      db.select({ id: follows.ownerId }).from(follows).where(eq(follows.followerId, followerId)),
  });

type Seam = "database" | "absent" | "never";

const withSeam = <A>(
  effect: Effect.Effect<A, never, CurrentViewer>,
  viewer: AppUser | null,
  seam: Seam,
) => {
  const provided = effect.pipe(
    Effect.provide(Auth.SessionContext.viewerLayer(CurrentViewer, viewer)),
  );
  switch (seam) {
    case "absent":
      return provided;
    case "never":
      return Effect.provide(provided, Auth.OwnedAccess.isFollowerNever);
    case "database":
      return Effect.provide(provided, databaseFollowers());
  }
};

const describeViewer = (viewer: AppUser | null) =>
  viewer === null ? "anonymous" : `${viewer.id} (${viewer.role})`;

describe("ownedListFilter agrees with canView, row for row", () => {
  for (const seam of ["database", "absent", "never"] as const) {
    for (const viewer of VIEWERS) {
      it(`posts (with drafts): ${describeViewer(viewer)}, follower seam ${seam}`, async () => {
        const all = await db.select().from(posts);
        const expected = new Set<string>();
        for (const row of all) {
          const visible = await Effect.runPromise(
            withSeam(
              owned.canView({
                ownerId: row.ownerId,
                visibility: row.visibility as Auth.OwnedAccess.Visibility,
                draft: row.draft,
              }),
              viewer,
              seam,
            ),
          );
          if (visible) expected.add(row.id);
        }
        const scope = await Effect.runPromise(withSeam(owned.readScope, viewer, seam));
        const listed = await db
          .select({ id: posts.id })
          .from(posts)
          .where(
            ownedListFilter({
              owner: posts.ownerId,
              visibility: posts.visibility,
              draft: posts.draft,
            })(scope),
          );
        expect(new Set(listed.map((row) => row.id))).toEqual(expected);
      });

      it(`gardens (no draft axis): ${describeViewer(viewer)}, follower seam ${seam}`, async () => {
        const all = await db.select().from(gardens);
        const expected = new Set<string>();
        for (const row of all) {
          const visible = await Effect.runPromise(
            withSeam(
              owned.canView({
                ownerId: row.ownerId,
                visibility: row.visibility as Auth.OwnedAccess.Visibility,
              }),
              viewer,
              seam,
            ),
          );
          if (visible) expected.add(row.id);
        }
        const scope = await Effect.runPromise(withSeam(owned.readScope, viewer, seam));
        const listed = await db
          .select({ id: gardens.id })
          .from(gardens)
          .where(
            ownedListFilter({ owner: gardens.ownerId, visibility: gardens.visibility })(scope),
          );
        expect(new Set(listed.map((row) => row.id))).toEqual(expected);
      });
    }
  }

  it("is not vacuous: each audience sees what it should, not nothing and not everything", async () => {
    const listFor = async (viewer: AppUser | null) => {
      const scope = await Effect.runPromise(withSeam(owned.readScope, viewer, "database"));
      const rows = await db
        .select({ id: posts.id })
        .from(posts)
        .where(
          ownedListFilter({
            owner: posts.ownerId,
            visibility: posts.visibility,
            draft: posts.draft,
          })(scope),
        );
      return new Set(rows.map((row) => row.id));
    };
    // Anonymous: the three published public rows.
    expect(await listFor(null)).toEqual(
      new Set(["alice:public:published", "bob:public:published", "carol:public:published"]),
    );
    // bob follows alice: public rows, his own six, and alice's published followers row.
    const bob = await listFor({ id: "bob", role: "user" });
    expect(bob.has("alice:followers:published")).toBe(true);
    expect(bob.has("alice:followers:draft")).toBe(false);
    expect(bob.has("alice:private:published")).toBe(false);
    expect(bob.has("carol:followers:published")).toBe(false);
    expect([...bob].filter((id) => id.startsWith("bob:"))).toHaveLength(6);
    // A moderator sees the whole corpus.
    expect(await listFor({ id: "mod", role: "moderator" })).toHaveLength(18);
  });
});

describe("ownedListFilter's rendered SQL", () => {
  const dialect = new PgDialect();
  const render = (scope: Auth.OwnedAccess.OwnedReadScope, withDraft = true) => {
    const where = ownedListFilter({
      owner: posts.ownerId,
      visibility: posts.visibility,
      ...(withDraft ? { draft: posts.draft } : {}),
    })(scope);
    if (where === undefined) return undefined;
    const { sql, params } = dialect.sqlToQuery(where);
    return { sql, params };
  };

  it("is no filter at all for the all scope", () => {
    expect(render({ kind: "all" })).toBeUndefined();
  });

  it("is public-and-published for the public scope, and omits draft on a table without one", () => {
    expect(render({ kind: "public" })).toEqual({
      sql: '("posts"."visibility" = $1 and "posts"."draft" = $2)',
      params: ["public", false],
    });
    expect(render({ kind: "public" }, false)).toEqual({
      sql: '"posts"."visibility" = $1',
      params: ["public"],
    });
  });

  it("nests the follow set as a subquery — never a materialised list", () => {
    const following = db
      .select({ id: follows.ownerId })
      .from(follows)
      .where(eq(follows.followerId, "bob"));
    const rendered = render({
      kind: "member",
      userId: "bob",
      following: Auth.OwnedAccess.subquery(following),
    });
    expect(rendered?.sql).toContain('"posts"."owner_id" in (select "owner_id" from "follows"');
    expect(rendered?.params).toEqual(["public", false, "bob", "followers", "bob", false]);
  });

  it("drops the followers arm for nobody, and for a follow set it cannot render (fail closed)", () => {
    const nobody = render({ kind: "member", userId: "bob", following: Auth.OwnedAccess.nobody });
    const foreign = render({
      kind: "member",
      userId: "bob",
      following: Auth.OwnedAccess.subquery(["alice", "carol"]),
    });
    for (const rendered of [nobody, foreign]) {
      expect(rendered?.sql).not.toContain("followers");
      expect(rendered?.params).toEqual(["public", false, "bob"]);
    }
  });
});
