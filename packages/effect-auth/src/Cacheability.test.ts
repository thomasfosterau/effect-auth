/**
 * The two cache questions (#191, #221 (e)), ported from the applications:
 * `bypassesCacheForFreshness` / `shouldIncludeDeletedE` (gardeneria
 * `packages/database/tests/guards.test.ts`) and `isPubliclyServeable`'s
 * conservative posture (gardeneria `apps/api/src/cache.ts`).
 *
 * The library-side property: a representation `OwnedAccess.serveableAxes`
 * admit is visible to every viewer, anonymous included — the decision is
 * viewer-independent, which is exactly what a cache with no viewer in its key
 * needs — and every representation it refuses is hidden from someone.
 */
import { describe, expect, it } from "vite-plus/test";
import { Context, Effect, Layer, Option } from "effect";
import * as Cacheability from "./Cacheability.ts";
import * as Guard from "./Guard.ts";
import * as Ladder from "./Ladder.ts";
import * as OwnedAccess from "./OwnedAccess.ts";
import * as SessionContext from "./SessionContext.ts";

interface AppUser {
  readonly id: string;
  readonly role: string;
}
class CurrentViewer extends Context.Service<CurrentViewer, Option.Option<AppUser>>()(
  "@test/Cacheability/CurrentViewer",
) {}

const Roles = Ladder.make(["user", "contributor", "moderator", "admin"]);
const Axes = Roles.axes({ viewPrivate: "moderator", viewDeleted: "moderator" });
const guards = Guard.make({ ladder: Roles, viewer: CurrentViewer });
const owned = OwnedAccess.make({ guards, viewPrivate: Axes.viewPrivate });

const admin: AppUser = { id: "u-admin", role: "admin" };
const moderator: AppUser = { id: "u-moderator", role: "moderator" };
const contributor: AppUser = { id: "u-contributor", role: "contributor" };
const member: AppUser = { id: "u-member", role: "user" };

const run = <A>(effect: Effect.Effect<A, never, CurrentViewer>, viewer: AppUser | null): A =>
  Effect.runSync(Effect.provide(effect, SessionContext.viewerLayer(CurrentViewer, viewer)));

describe("bypassesForFreshness", () => {
  const bypasses = Cacheability.bypassesForFreshness(guards, [Axes.viewPrivate, Axes.viewDeleted]);

  it("is true for moderator and above — the union of the two read-visibility axes", () => {
    expect(run(bypasses, admin)).toBe(true);
    expect(run(bypasses, moderator)).toBe(true);
    expect(run(bypasses, contributor)).toBe(false);
    expect(run(bypasses, member)).toBe(false);
    expect(run(bypasses, null)).toBe(false);
  });

  it("is the union: either axis alone routes the viewer around the cache", () => {
    const Split = Roles.axes({ viewPrivate: "admin", viewDeleted: "contributor" });
    const split = Cacheability.bypassesForFreshness(guards, [Split.viewPrivate, Split.viewDeleted]);
    expect(run(split, contributor)).toBe(true);
    expect(run(split, member)).toBe(false);
  });
});

describe("shouldIncludeDeleted", () => {
  const include = Cacheability.shouldIncludeDeleted(guards, Axes.viewDeleted);

  it("is false when the input does not opt in, regardless of role", () => {
    expect(run(include({}), admin)).toBe(false);
    expect(run(include({ includeDeleted: false }), admin)).toBe(false);
  });

  it("requires BOTH the opt-in and the rung", () => {
    expect(run(include({ includeDeleted: true }), admin)).toBe(true);
    expect(run(include({ includeDeleted: true }), moderator)).toBe(true);
    // Opted in but below the rung → still excluded (permission wins).
    expect(run(include({ includeDeleted: true }), member)).toBe(false);
    expect(run(include({ includeDeleted: true }), null)).toBe(false);
  });
});

describe("publiclyServeable", () => {
  const serveable = Cacheability.publiclyServeable([
    { attribute: "visibility", equals: "public" },
    { attribute: "moderationState", equals: "approved", optional: true },
    { attribute: "draft", equals: false, optional: true },
    { attribute: "deletedAt", absent: true },
  ]);

  it("admits a representation whose every axis holds the serveable literal", () => {
    expect(serveable({ visibility: "public", moderationState: "approved", draft: false })).toBe(
      true,
    );
    expect(serveable({ visibility: "public" })).toBe(true);
  });

  it("refuses a present axis whose value is anything but the serveable literal", () => {
    for (const visibility of ["private", "followers", "", null, "PUBLIC", "unlisted"]) {
      expect(serveable({ visibility }), String(visibility)).toBe(false);
    }
    expect(serveable({ visibility: "public", moderationState: "pending" })).toBe(false);
    expect(serveable({ visibility: "public", moderationState: null })).toBe(false);
    expect(serveable({ visibility: "public", draft: true })).toBe(false);
    expect(serveable({ visibility: "public", draft: "false" })).toBe(false);
  });

  it("refuses a representation missing a required axis — never 'probably fine'", () => {
    expect(serveable({})).toBe(false);
    expect(serveable({ moderationState: "approved" })).toBe(false);
  });

  it("refuses a tombstone whatever its deletedAt holds, null included", () => {
    expect(serveable({ visibility: "public", deletedAt: "2026-01-01T00:00:00Z" })).toBe(false);
    expect(serveable({ visibility: "public", deletedAt: null })).toBe(false);
  });

  it("refuses anything that is not an attribute record", () => {
    for (const notARecord of [null, undefined, "public", 1, [], ["public"]]) {
      expect(serveable(notARecord)).toBe(false);
    }
  });
});

describe("OwnedAccess.serveableAxes", () => {
  const serveable = Cacheability.publiclyServeable(OwnedAccess.serveableAxes);
  const viewers = [null, member, contributor, moderator, admin, { id: "owner", role: "user" }];
  const everyoneFollows = Layer.succeed(OwnedAccess.IsFollower, {
    isFollower: () => Effect.succeed(true),
    following: () => OwnedAccess.nobody,
  });

  const visibleToAll = (row: OwnedAccess.OwnedRow) =>
    viewers.every((viewer) =>
      Effect.runSync(
        owned
          .canView(row)
          .pipe(
            Effect.provide(
              Layer.merge(SessionContext.viewerLayer(CurrentViewer, viewer), everyoneFollows),
            ),
          ),
      ),
    );

  it("admit a row exactly when every viewer, anonymous included, may see it", () => {
    for (const visibility of ["public", "followers", "private"] as const) {
      for (const draft of [undefined, false, true]) {
        const row: OwnedAccess.OwnedRow = {
          ownerId: "owner",
          visibility,
          ...(draft === undefined ? {} : { draft }),
        };
        const attributes = { visibility, ...(draft === undefined ? {} : { draft }) };
        expect(serveable(attributes), `${visibility}/${String(draft)}`).toBe(visibleToAll(row));
      }
    }
  });

  it("refuse an owned representation whose projection dropped visibility", () => {
    expect(serveable({ draft: false })).toBe(false);
  });
});
