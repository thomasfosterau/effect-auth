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
import * as Authorizer from "./Authorizer.ts";
import * as Entity from "./Entity.ts";
import * as Guard from "./Guard.ts";
import * as Ladder from "./Ladder.ts";
import * as OwnedAccess from "./OwnedAccess.ts";
import * as Policy from "./Policy.ts";
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

  it('are read policies: every permit is scoped to Action::"read"', () => {
    for (const policy of owned.policies) {
      expect(policy.action, policy.id).toEqual(Policy.eq(Entity.ref("Action", "read")));
    }
  });
});

describe("handed to an Authorizer, the policies decide reads and nothing else", () => {
  /** `owned.policies` alone, as an application's Authorizer would hold them. */
  const authorize = (
    principal: Entity.EntityRef,
    action: string,
    resource: Entity.EntityRef,
    resolved: ReadonlyArray<Entity.Entity>,
    follows: boolean,
  ): Promise<boolean> =>
    Effect.runPromise(
      Effect.gen(function* () {
        const authorizer = yield* Authorizer.Authorizer;
        return yield* authorizer.check({ action, resource, context: { follows } });
      }).pipe(
        Authorizer.CurrentPrincipal.provide(principal),
        Effect.provide(Authorizer.Authorizer.layer({ policies: owned.policies })),
        Effect.provideService(Authorizer.EntityResolver, Authorizer.memoryEntityResolver(resolved)),
      ),
    );

  const memberEntity = Entity.entity(Entity.ref("User", member.id), {
    attributes: { role: member.role },
  });
  const moderatorEntity = Entity.entity(Entity.ref("User", moderator.id), {
    attributes: { role: moderator.role },
  });
  const otherMemberEntity = Entity.entity(Entity.ref("User", otherMember.id), {
    attributes: { role: otherMember.role },
  });

  /** An owned row owned by `member`, as the resolver sees it. */
  const ownedByMember = (id: string, visibility: OwnedAccess.Visibility, draft = false) =>
    Entity.entity(Entity.ref("Owned", id), {
      attributes: {
        owner: Entity.entityValue(Entity.ref("User", member.id)),
        visibility,
        draft,
      },
    });

  it("a user's update and delete on a public row are denied, owner included", async () => {
    const publicRow = ownedByMember("public-row", "public");
    const resolved = [publicRow, memberEntity, otherMemberEntity];
    for (const principal of [memberEntity, otherMemberEntity]) {
      expect(
        await authorize(principal.ref, "read", publicRow.ref, resolved, false),
        `${principal.ref.id} reads`,
      ).toBe(true);
      for (const action of ["update", "delete"]) {
        expect(
          await authorize(principal.ref, action, publicRow.ref, resolved, false),
          `${principal.ref.id} ${action}`,
        ).toBe(false);
      }
    }
  });

  it("the viewPrivate axis reads a private row and still cannot update or delete it", async () => {
    const privateRow = ownedByMember("private-row", "private");
    const resolved = [privateRow, memberEntity, moderatorEntity];
    for (const action of ["update", "delete"]) {
      expect(await authorize(moderatorEntity.ref, action, privateRow.ref, resolved, false)).toBe(
        false,
      );
      expect(await authorize(memberEntity.ref, action, privateRow.ref, resolved, false)).toBe(
        false,
      );
    }
    expect(await authorize(moderatorEntity.ref, "read", privateRow.ref, resolved, false)).toBe(
      true,
    );
    expect(await authorize(memberEntity.ref, "read", privateRow.ref, resolved, false)).toBe(true);
  });

  it("read decisions agree with canView, row for row, for every viewer", async () => {
    const viewers: ReadonlyArray<AppUser | null> = [
      null,
      member,
      otherMember,
      contributor,
      moderator,
    ];
    for (const visibility of ["public", "followers", "private"] as const) {
      for (const draft of [false, true]) {
        const resource = ownedByMember(`row-${visibility}-${draft}`, visibility, draft);
        for (const viewer of viewers) {
          const principal =
            viewer === null ? Entity.ref("Anonymous", "anonymous") : Entity.ref("User", viewer.id);
          const resolved = [
            resource,
            memberEntity,
            ...(viewer === null
              ? []
              : [Entity.entity(principal, { attributes: { role: viewer.role } })]),
          ];
          const followsOwner = viewer?.id === otherMember.id;
          expect(
            await authorize(principal, "read", resource.ref, resolved, followsOwner),
            `${viewer?.id ?? "anonymous"}, ${visibility}, draft=${draft}`,
          ).toBe(canView(row(visibility, draft), viewer, follows));
        }
      }
    }
  });
});
