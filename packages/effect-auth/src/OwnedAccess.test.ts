/**
 * Owned-material read access (#190, #221 (c)), ported from the applications'
 * guard suite (gardeneria `packages/database/tests/guards.test.ts`:
 * `canViewOwnedE`, `ownedReadScopeE`, the `IsFollower` seam and
 * `isFollowerNever`) with the draft axis (gardeneria #1118).
 *
 * The list-filter half — that the rendered `WHERE` agrees with `canView` on
 * every row — is pinned against a real Postgres in
 * `@thomasfosterau/effect-auth-drizzle`'s `OwnedListFilter.test.ts`.
 */
import { describe, expect, it } from "vite-plus/test";
import { Context, Effect, Layer, Option } from "effect";
import * as Guard from "./Guard.ts";
import * as Ladder from "./Ladder.ts";
import * as OwnedAccess from "./OwnedAccess.ts";
import * as SessionContext from "./SessionContext.ts";

interface AppUser {
  readonly id: string;
  readonly role: string;
}
class CurrentViewer extends Context.Service<CurrentViewer, Option.Option<AppUser>>()(
  "@test/OwnedAccess/CurrentViewer",
) {}

const Roles = Ladder.make(["user", "contributor", "moderator", "admin"]);
const Axes = Roles.axes({ viewPrivate: "moderator" });
const guards = Guard.make({ ladder: Roles, viewer: CurrentViewer });
const owned = OwnedAccess.make({ guards, viewPrivate: Axes.viewPrivate });

const admin: AppUser = { id: "u-admin", role: "admin" };
const moderator: AppUser = { id: "u-moderator", role: "moderator" };
const contributor: AppUser = { id: "u-contributor", role: "contributor" };
const member: AppUser = { id: "u-member", role: "user" };
const otherMember: AppUser = { id: "u-other", role: "user" };

/** `otherMember` follows `member`, and nobody else follows anybody. */
const follows = Layer.succeed(OwnedAccess.IsFollower, {
  isFollower: (followerId, ownerId) =>
    Effect.succeed(followerId === otherMember.id && ownerId === member.id),
  following: (followerId) => OwnedAccess.subquery(`following(${followerId})`),
});
const everyoneFollows = Layer.succeed(OwnedAccess.IsFollower, {
  isFollower: () => Effect.succeed(true),
  following: () => OwnedAccess.subquery("everyone"),
});

const canView = (
  row: OwnedAccess.OwnedRow,
  viewer: AppUser | null,
  follower?: Layer.Layer<OwnedAccess.IsFollower>,
): boolean => {
  const withViewer = owned
    .canView(row)
    .pipe(Effect.provide(SessionContext.viewerLayer(CurrentViewer, viewer)));
  return Effect.runSync(follower === undefined ? withViewer : Effect.provide(withViewer, follower));
};

const row = (visibility: OwnedAccess.Visibility, draft?: boolean): OwnedAccess.OwnedRow => ({
  ownerId: member.id,
  visibility,
  ...(draft === undefined ? {} : { draft }),
});

describe("canView (the owned-material read predicate)", () => {
  it("public: everyone, anonymous included", () => {
    expect(canView(row("public"), null)).toBe(true);
    expect(canView(row("public"), otherMember)).toBe(true);
  });

  it("private: the owner and the viewPrivate axis, nobody else", () => {
    expect(canView(row("private"), member)).toBe(true);
    expect(canView(row("private"), moderator)).toBe(true);
    expect(canView(row("private"), admin)).toBe(true);
    expect(canView(row("private"), otherMember)).toBe(false);
    expect(canView(row("private"), contributor)).toBe(false);
    expect(canView(row("private"), null)).toBe(false);
  });

  it("followers: the owner, the viewPrivate axis, and the owner's followers via the seam", () => {
    expect(canView(row("followers"), member)).toBe(true);
    expect(canView(row("followers"), moderator)).toBe(true);
    expect(canView(row("followers"), otherMember, follows)).toBe(true);
    expect(canView(row("followers"), contributor, follows)).toBe(false);
    expect(canView(row("followers"), null, follows)).toBe(false);
  });

  it("followers: fails closed when no IsFollower layer is provided at all", () => {
    expect(canView(row("followers"), otherMember)).toBe(false);
  });

  it("followers: isFollowerNever is the same fail-closed answer, made explicit", () => {
    expect(canView(row("followers"), otherMember, OwnedAccess.isFollowerNever)).toBe(false);
  });

  it("private never consults the follower seam", () => {
    expect(canView(row("private"), otherMember, everyoneFollows)).toBe(false);
  });

  it("a draft is hidden from everyone but the owner and the viewPrivate axis, whatever its visibility", () => {
    for (const visibility of ["public", "followers", "private"] as const) {
      expect(canView(row(visibility, true), member), `owner, ${visibility}`).toBe(true);
      expect(canView(row(visibility, true), moderator), `moderator, ${visibility}`).toBe(true);
      expect(canView(row(visibility, true), otherMember, everyoneFollows)).toBe(false);
      expect(canView(row(visibility, true), null)).toBe(false);
    }
  });

  it("draft: false reads exactly as an omitted draft axis", () => {
    for (const visibility of ["public", "followers", "private"] as const) {
      for (const viewer of [member, otherMember, moderator, null]) {
        expect(canView(row(visibility, false), viewer, follows)).toBe(
          canView(row(visibility), viewer, follows),
        );
      }
    }
  });

  it("an owner whose id matches the anonymous sentinel is still not anonymous's row", () => {
    const sentinel = { ownerId: "anonymous", visibility: "private" as const };
    expect(canView(sentinel, null)).toBe(false);
  });
});

describe("readScope (the owned-material list scope)", () => {
  const scope = (viewer: AppUser | null, follower?: Layer.Layer<OwnedAccess.IsFollower>) => {
    const withViewer = owned.readScope.pipe(
      Effect.provide(SessionContext.viewerLayer(CurrentViewer, viewer)),
    );
    return Effect.runSync(
      follower === undefined ? withViewer : Effect.provide(withViewer, follower),
    );
  };

  it("anonymous is public", () => {
    expect(scope(null)).toEqual({ kind: "public" });
  });

  it("the viewPrivate axis and above is all", () => {
    expect(scope(moderator)).toEqual({ kind: "all" });
    expect(scope(admin)).toEqual({ kind: "all" });
  });

  it("a member below the axis carries their id and their follow set", () => {
    expect(scope(contributor, follows)).toEqual({
      kind: "member",
      userId: contributor.id,
      following: OwnedAccess.subquery(`following(${contributor.id})`),
    });
  });

  it("the follow set fails closed to nobody when the seam is absent", () => {
    expect(scope(member)).toEqual({
      kind: "member",
      userId: member.id,
      following: OwnedAccess.nobody,
    });
    expect(scope(member, OwnedAccess.isFollowerNever)).toEqual({
      kind: "member",
      userId: member.id,
      following: OwnedAccess.nobody,
    });
  });
});

describe("the policies canView decides", () => {
  it("are plain declarative policies with stable ids", () => {
    expect(owned.policies.map((policy) => policy.id)).toEqual([
      "owned:public",
      "owned:owner",
      "owned:view-private",
      "owned:follower",
    ]);
    for (const policy of owned.policies) expect(policy._tag).toBe("DeclarativePolicy");
  });
});
