import { describe, expect, it } from "vite-plus/test";
import { Context, Data, Effect, Option, Result } from "effect";
import * as Guard from "../Guard.ts";
import * as Ladder from "../Ladder.ts";
import * as Testing from "./index.ts";

interface AppUser {
  readonly id: string;
  readonly role: string;
}

class CurrentViewer extends Context.Service<CurrentViewer, Option.Option<AppUser>>()(
  "@test/CurrentViewer",
) {}

class NotFound extends Data.TaggedError("NotFound")<{}> {}

const Roles = Ladder.make(["user", "contributor", "moderator", "admin"]);
const Axes = Roles.axes({ moderate: "moderator" });
const guards = Guard.make({ ladder: Roles, viewer: CurrentViewer });

const viewerAt = (role: string): AppUser => ({ id: `u-${role}`, role });
const author: AppUser = { id: "u-author", role: "user" };

const editPost = guards.requireOwnerOrRole(author.id, Axes.moderate);
const deletePost = guards.requireRoleAtLeast(Axes.moderate);
const readPost = Effect.flatMap(guards.isOwnerOrRole(author.id, Axes.moderate), (visible) =>
  visible ? Effect.succeed("post") : Effect.fail(new NotFound()),
);
const unguarded = Effect.succeed("done");

const mismatchesOf = (
  expectation: Effect.Effect<void, Testing.GuardExpectationError, never>,
): ReadonlyArray<Testing.GuardMismatch> => {
  const result = Effect.runSync(Effect.result(expectation));
  return Result.isFailure(result) ? result.failure.mismatches : [];
};

describe("expectGuarded", () => {
  it("passes an owner-or-rung write gate", async () => {
    await Effect.runPromise(
      Testing.expectGuarded(editPost, CurrentViewer, {
        ladder: Roles,
        min: Axes.moderate,
        viewerAt,
        owner: author,
      }),
    );
  });

  it("passes a read that maps every refusal to not-found", async () => {
    await Effect.runPromise(
      Testing.expectGuarded(readPost, CurrentViewer, {
        ladder: Roles,
        min: Axes.moderate,
        viewerAt,
        owner: author,
        access: "read",
      }),
    );
  });

  it("fails every refusal case when the guard is removed", () => {
    expect(
      mismatchesOf(
        Testing.expectGuarded(unguarded, CurrentViewer, {
          ladder: Roles,
          min: Axes.moderate,
          viewerAt,
          owner: author,
        }),
      ),
    ).toEqual([
      { case: "anonymous", expected: "Unauthorized", actual: "allowed" },
      { case: "below contributor", expected: "Forbidden", actual: "allowed" },
    ]);
  });

  it("fails the owner case when the gate ignores ownership", () => {
    expect(
      mismatchesOf(
        Testing.expectGuarded(deletePost, CurrentViewer, {
          ladder: Roles,
          min: Axes.moderate,
          viewerAt,
          owner: author,
        }),
      ),
    ).toEqual([{ case: "owner", expected: "allowed", actual: "Forbidden" }]);
  });

  it("fails a read that answers 403 instead of 404", () => {
    expect(
      mismatchesOf(
        Testing.expectGuarded(deletePost, CurrentViewer, {
          ladder: Roles,
          min: Axes.moderate,
          viewerAt,
          access: "read",
        }),
      ),
    ).toEqual([
      { case: "anonymous", expected: "NotFound", actual: "Unauthorized" },
      { case: "below contributor", expected: "NotFound", actual: "Forbidden" },
    ]);
  });

  it("fails a gate set one rung too high", () => {
    const tooHigh = guards.requireRoleAtLeast("admin");
    expect(
      mismatchesOf(
        Testing.expectGuarded(tooHigh, CurrentViewer, {
          ladder: Roles,
          min: "moderator",
          viewerAt,
        }),
      ),
    ).toEqual([{ case: "at moderator", expected: "allowed", actual: "Forbidden" }]);
  });

  it("reports a defect as a defect, not a refusal", () => {
    expect(mismatchesOf(Testing.expectRefusesAnonymous(Effect.die("boom"), CurrentViewer))).toEqual(
      [{ case: "anonymous", expected: "Unauthorized", actual: "defect" }],
    );
  });
});

describe("the single-case helpers", () => {
  it("expectRefusesAnonymous passes a gate and fails without one", async () => {
    await Effect.runPromise(Testing.expectRefusesAnonymous(deletePost, CurrentViewer));
    await Effect.runPromise(
      Testing.expectRefusesAnonymous(readPost, CurrentViewer, { access: "read" }),
    );
    expect(mismatchesOf(Testing.expectRefusesAnonymous(unguarded, CurrentViewer))).toHaveLength(1);
  });

  it("expectRefusesBelow passes a rung gate and fails without one", async () => {
    const options = { ladder: Roles, min: Axes.moderate, viewerAt };
    await Effect.runPromise(Testing.expectRefusesBelow(deletePost, CurrentViewer, options));
    expect(mismatchesOf(Testing.expectRefusesBelow(unguarded, CurrentViewer, options))).toEqual([
      { case: "below contributor", expected: "Forbidden", actual: "allowed" },
    ]);
  });

  it("expectRefusesBelow checks only admission at the lowest rung", async () => {
    await Effect.runPromise(
      Testing.expectRefusesBelow(guards.requireRoleAtLeast("user"), CurrentViewer, {
        ladder: Roles,
        min: "user",
        viewerAt,
      }),
    );
  });

  it("expectAllowsOwner passes an owner gate and fails a rung-only one", async () => {
    await Effect.runPromise(Testing.expectAllowsOwner(editPost, CurrentViewer, author));
    expect(mismatchesOf(Testing.expectAllowsOwner(deletePost, CurrentViewer, author))).toEqual([
      { case: "owner", expected: "allowed", actual: "Forbidden" },
    ]);
  });

  it("the error message names every mismatch", () => {
    const result = Effect.runSync(
      Effect.result(Testing.expectRefusesAnonymous(unguarded, CurrentViewer)),
    );
    expect(Result.isFailure(result) && result.failure.message).toBe(
      "guard expectations failed: anonymous: expected Unauthorized, got allowed",
    );
  });
});
