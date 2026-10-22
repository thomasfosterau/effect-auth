/**
 * The ordered role ladder (#188), ported from the applications' own ladder
 * suite (gardeneria `packages/database/tests/roles.test.ts`, website's
 * equivalent over `user < commenter < editor < admin`) and extended with the
 * two things the library adds: the kernel bridge (`Policy.roleAtLeast`) and
 * its validation against an `AuthorizationModel`.
 *
 * Every rung is driven against every axis, so a rung gaining access it should
 * not have is a test failure rather than a passing refactor.
 */
import { describe, expect, it } from "vite-plus/test";
import { Effect, Schema } from "effect";
import * as AuthorizationModel from "./AuthorizationModel.ts";
import * as Entity from "./Entity.ts";
import * as Ladder from "./Ladder.ts";
import * as Policy from "./Policy.ts";

// Gardeneria's ladder and axes — the superset of the three applications.
const Roles = Ladder.make(["user", "contributor", "moderator", "admin"]);
type Role = Ladder.RungOf<typeof Roles>;
const Axes = Roles.axes({
  corpusWrite: "contributor",
  moderate: "moderator",
  viewPrivate: "moderator",
  viewDeleted: "moderator",
});

const NOT_RUNGS = ["", "ADMIN", "Admin", "superadmin", "owner", "editor", "root"];

describe("Ladder.make", () => {
  it("keeps the rungs in declaration order, least → most privileged", () => {
    expect(Roles.rungs).toEqual(["user", "contributor", "moderator", "admin"]);
  });

  it("refuses an empty ladder and a duplicate rung", () => {
    // Non-empty by type, emptied at runtime: the input an untyped caller can pass.
    const emptied: [string, ...Array<string>] = ["x"];
    emptied.pop();
    expect(() => Ladder.make(emptied)).toThrow(/at least one rung/);
    expect(() => Ladder.make(["user", "admin", "user"])).toThrow(/duplicate rung "user"/);
  });

  it("is frozen: the rung array cannot be mutated into a different order", () => {
    expect(Object.isFrozen(Roles.rungs)).toBe(true);
    expect(Object.isFrozen(Roles)).toBe(true);
  });

  it("serves a second application's ladder unchanged (website's rungs)", () => {
    const Website = Ladder.make(["user", "commenter", "editor", "admin"]);
    expect(Website.hasAtLeast({ role: "editor" }, "commenter")).toBe(true);
    expect(Website.hasAtLeast({ role: "commenter" }, "editor")).toBe(false);
    // A rung of one ladder is not a rung of another.
    expect(Website.hasAtLeast({ role: "moderator" }, "user")).toBe(false);
  });
});

describe("rank", () => {
  it("reads the ordering straight off the rungs", () => {
    expect(Roles.rungs.map(Roles.rank)).toEqual([0, 1, 2, 3]);
  });

  it("ranks a string that is not a rung below every real rung (fails closed)", () => {
    for (const notARung of NOT_RUNGS) {
      expect(Roles.rank(notARung)).toBe(-1);
      expect(Roles.isRung(notARung)).toBe(false);
    }
    expect(Roles.isRung(3)).toBe(false);
    expect(Roles.isRung("moderator")).toBe(true);
  });
});

describe("hasAtLeast", () => {
  it("is true for every rung at or above the minimum, false below (all 4×4 pairs)", () => {
    for (const held of Roles.rungs) {
      for (const min of Roles.rungs) {
        expect(Roles.hasAtLeast({ role: held }, min), `${held} ≥ ${min}`).toBe(
          Roles.rank(held) >= Roles.rank(min),
        );
      }
    }
  });

  it("is reflexive — every rung satisfies itself", () => {
    for (const role of Roles.rungs) expect(Roles.hasAtLeast({ role }, role)).toBe(true);
  });

  it("denies an anonymous viewer at every rung and every axis", () => {
    for (const min of [...Roles.rungs, ...Object.values(Axes)]) {
      expect(Roles.hasAtLeast(null, min)).toBe(false);
      expect(Roles.hasAtLeast(undefined, min)).toBe(false);
    }
  });

  it("denies a role string that is not on the ladder, at every rung and every axis", () => {
    for (const min of [...Roles.rungs, ...Object.values(Axes)]) {
      for (const notARung of NOT_RUNGS) {
        expect(Roles.hasAtLeast({ role: notARung }, min)).toBe(false);
      }
    }
  });

  it("fails closed even against an off-ladder minimum smuggled in by a cast", () => {
    expect(Roles.hasAtLeast({ role: "nope" }, "also-nope" as Role)).toBe(false);
    expect(Roles.hasAtLeast({ role: "admin" }, "also-nope" as Role)).toBe(true);
    expect(Roles.atOrAbove("also-nope" as Role)).toEqual([]);
  });
});

describe("axes", () => {
  it("resolve to the rung each was declared on", () => {
    expect(Axes.corpusWrite).toEqual({
      _tag: "LadderAxis",
      name: "corpusWrite",
      min: "contributor",
    });
    expect(Ladder.minOf(Axes.moderate)).toBe("moderator");
    expect(Ladder.isAxis(Axes.viewPrivate)).toBe(true);
    expect(Ladder.isAxis("moderator")).toBe(false);
  });

  it("refuse a rung that is not on the ladder", () => {
    expect(() => Roles.axis("typo", "moderater" as Role)).toThrow(
      /"moderater", which is not a rung/,
    );
  });

  it("the base rung satisfies none of them, and the top rung satisfies all", () => {
    for (const axis of Object.values(Axes)) {
      expect(Roles.hasAtLeast({ role: "admin" }, axis)).toBe(true);
      expect(Roles.hasAtLeast({ role: "user" }, axis)).toBe(false);
    }
  });

  it("stay separate questions: a contributor writes the corpus but cannot moderate", () => {
    expect(Roles.hasAtLeast({ role: "contributor" }, Axes.corpusWrite)).toBe(true);
    expect(Roles.hasAtLeast({ role: "contributor" }, Axes.moderate)).toBe(false);
    expect(Roles.hasAtLeast({ role: "contributor" }, Axes.viewPrivate)).toBe(false);
  });

  it("moving an axis is a single-site change", () => {
    // The same call sites, against a ladder whose `moderate` axis moved down a
    // rung: nothing but the declaration differs.
    const Moved = Roles.axes({ moderate: "contributor" });
    expect(Roles.hasAtLeast({ role: "contributor" }, Moved.moderate)).toBe(true);
    expect(Roles.hasAtLeast({ role: "contributor" }, Axes.moderate)).toBe(false);
  });

  it("atOrAbove lists exactly the rungs that satisfy an axis", () => {
    expect(Roles.atOrAbove(Axes.corpusWrite)).toEqual(["contributor", "moderator", "admin"]);
    expect(Roles.atOrAbove("admin")).toEqual(["admin"]);
    expect(Roles.atOrAbove("user")).toEqual(Roles.rungs);
  });
});

// ---------------------------------------------------------------------------
// The kernel bridge
// ---------------------------------------------------------------------------

const principal = (role: string | undefined) =>
  Entity.entity(Entity.ref("User", "u1"), role === undefined ? {} : { attributes: { role } });

const decide = (policy: Policy.DeclarativePolicy, role: string | undefined) =>
  Effect.runSync(
    Policy.decide(
      [policy],
      Policy.request({
        principal: Entity.ref("User", "u1"),
        action: Entity.ref("Action", "write"),
        resource: Entity.ref("Taxon", "t1"),
      }),
      Entity.slice([principal(role)]),
    ),
  );

describe("Policy.roleAtLeast", () => {
  it("agrees with hasAtLeast on every rung × axis pair, and on off-ladder roles", () => {
    for (const axis of Object.values(Axes)) {
      const policy = Policy.roleAtLeast(Roles, axis);
      for (const role of [...Roles.rungs, ...NOT_RUNGS]) {
        expect(decide(policy, role).allowed, `${role} on ${axis.name}`).toBe(
          Roles.hasAtLeast({ role }, axis),
        );
      }
    }
  });

  it("denies a principal with no role attribute (the anonymous / unknown-entity case)", () => {
    const decision = decide(Policy.roleAtLeast(Roles, Axes.corpusWrite), undefined);
    expect(decision.allowed).toBe(false);
    expect(decision.outcomes[0]?.result).toBe("error");
  });

  it("is plain data: it round-trips through the stored policy schema", () => {
    const policy = Policy.roleAtLeast(Roles, Axes.moderate, {
      resource: Policy.isType("Taxon"),
    });
    expect(policy.id).toBe("ladder:moderate");
    const decoded = Schema.decodeSync(Schema.fromJsonString(Policy.DeclarativePolicy))(
      Schema.encodeSync(Schema.fromJsonString(Schema.Unknown))(policy),
    );
    expect(decide(decoded, "moderator").allowed).toBe(true);
    expect(decide(decoded, "contributor").allowed).toBe(false);
  });

  it("ANDs a caller condition onto the ladder condition", () => {
    const policy = Policy.roleAtLeast(Roles, "user", {
      when: { _tag: "Eq", left: { _tag: "Lit", value: 1 }, right: { _tag: "Lit", value: 2 } },
    });
    expect(decide(policy, "admin").allowed).toBe(false);
  });

  it("reads a differently-named role attribute when told to", () => {
    const policy = Policy.roleAtLeast(Roles, "admin", { roleAttribute: "rung" });
    const decision = Effect.runSync(
      Policy.decide(
        [policy],
        Policy.request({
          principal: Entity.ref("User", "u1"),
          action: Entity.ref("Action", "write"),
          resource: Entity.ref("Taxon", "t1"),
        }),
        Entity.slice([Entity.entity(Entity.ref("User", "u1"), { attributes: { rung: "admin" } })]),
      ),
    );
    expect(decision.allowed).toBe(true);
  });
});

describe("Policy.roleAtLeast against an AuthorizationModel", () => {
  const model = AuthorizationModel.make({
    entities: {
      User: { attributes: Schema.Struct({ role: Schema.Literals(Roles.rungs) }) },
      Taxon: {},
    },
    actions: { write: { appliesTo: { principal: ["User"], resource: ["Taxon"] } } },
  });

  it("validates when the principal type declares the role attribute", () => {
    const policy = Policy.roleAtLeast(Roles, Axes.corpusWrite, {
      principal: Policy.isType("User"),
      action: Policy.eq(Entity.ref("Action", "write")),
      resource: Policy.isType("Taxon"),
    });
    expect(AuthorizationModel.validatePolicies(model, [policy])).toEqual([]);
  });

  it("flags a role attribute the principal type does not declare", () => {
    const policy = Policy.roleAtLeast(Roles, Axes.corpusWrite, {
      principal: Policy.isType("User"),
      roleAttribute: "rank",
    });
    expect(AuthorizationModel.validatePolicies(model, [policy])).toEqual([
      {
        policyId: "ladder:corpusWrite",
        message: 'condition reads principal.rank, but "User" declares no attribute "rank"',
      },
    ]);
  });

  it("still flags an undeclared principal type", () => {
    const policy = Policy.roleAtLeast(Roles, "admin", { principal: Policy.isType("Usr") });
    expect(AuthorizationModel.validatePolicies(model, [policy])).toHaveLength(1);
  });
});
