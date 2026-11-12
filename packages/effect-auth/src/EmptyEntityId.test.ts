/**
 * An empty entity id names no entity (#661).
 *
 * `Entity.ref("User", "")` used to be an ordinary principal: an owner permit
 * matched every row whose owner was `""`, in the kernel (`Policy.decidePure`)
 * and in the compiled read scope (`ReadScope.compile`) alike, so an integrator
 * using the empty id as a "no user" stand-in granted those rows to signed-out
 * callers. Both paths now refuse a request that names an empty id, and an
 * empty-id reference equals nothing, itself included.
 */
import { assert, describe, expect, it } from "vite-plus/test";
import { Context, Effect, Exit } from "effect";
import * as Option from "effect/Option";
import * as P from "effect/Predicate";
import * as Schema from "effect/Schema";
import * as Condition from "./Condition.ts";
import * as Entity from "./Entity.ts";
import * as Guard from "./Guard.ts";
import * as Ladder from "./Ladder.ts";
import * as OwnedAccess from "./OwnedAccess.ts";
import * as Policy from "./Policy.ts";
import * as ReadScope from "./ReadScope.ts";
import * as SessionContext from "./SessionContext.ts";

const nobody = Entity.ref("User", "");
const alice = Entity.ref("User", "alice");
const read = Entity.ref("Action", "read");
const doc = Entity.ref("Document", "doc-1");

/** The issue's repro: the owner may read. */
const ownerPermit = Policy.permit({
  id: "owner",
  when: Condition.eq(Condition.attr("resource", "owner"), Condition.principal),
});
const binding: ReadScope.Binding = {
  resourceType: "Document",
  attributes: { owner: { entity: "User" } },
};

const ownedBy = (owner: Entity.EntityRef): Entity.Entity =>
  Entity.entity(doc, { attributes: { owner: Entity.entityValue(owner) } });

const decide = (
  policies: ReadonlyArray<Policy.DeclarativePolicy>,
  request: { readonly principal: Entity.EntityRef; readonly resource?: Entity.Entity },
  action: Entity.EntityRef = read,
): Policy.Decision => {
  const resource = request.resource ?? ownedBy(nobody);
  return Policy.decidePure(
    policies,
    Policy.request({ principal: request.principal, action, resource: resource.ref }),
    Entity.slice([resource]),
  );
};

const compiled = (
  policies: ReadonlyArray<Policy.DeclarativePolicy>,
  principal: Entity.EntityRef,
): ReadScope.ReadScope => {
  const result = ReadScope.compile(policies, binding, { principal, action: read });
  assert(P.isTagged(result, "Exact"), "the policy set compiles exactly");
  return result.scope;
};

describe("Policy.decidePure refuses an empty entity id (#661)", () => {
  it("an empty-id principal does not own an empty-owner row", () => {
    const decision = decide([ownerPermit], { principal: nobody });
    expect(decision.allowed).toBe(false);
    expect(decision.reason).toBe("invalid-request");
    expect(decision.determining).toEqual([]);
  });

  it("an empty-id principal is refused even by a permit scoped only to its type", () => {
    const anyUser = Policy.permit({ id: "any-user", principal: Policy.isType("User") });
    expect(decide([anyUser], { principal: alice, resource: ownedBy(alice) }).allowed).toBe(true);
    expect(decide([anyUser], { principal: nobody }).allowed).toBe(false);
  });

  it("an empty-id action or resource is refused as well", () => {
    const everything = Policy.permit({ id: "everything" });
    expect(decide([everything], { principal: alice }, Entity.ref("Action", "")).reason).toBe(
      "invalid-request",
    );
    const unnamed = Entity.entity(Entity.ref("Document", ""));
    expect(decide([everything], { principal: alice, resource: unnamed }).reason).toBe(
      "invalid-request",
    );
  });

  it("an empty-id literal never equals an empty-owner attribute", () => {
    const literal = Policy.permit({
      id: "literal",
      when: Condition.eq(
        Condition.attr("resource", "owner"),
        Condition.lit(Entity.entityValue(nobody)),
      ),
    });
    expect(decide([literal], { principal: alice }).allowed).toBe(false);
  });

  it("a scope naming an empty-id entity matches nothing, its own ref included", () => {
    const hollowRole = Entity.ref("Role", "");
    const member = Entity.entity(alice, { parents: [hollowRole] });
    const policies = [
      Policy.permit({ id: "in", principal: Policy.inScope(hollowRole) }),
      Policy.permit({ id: "eq", resource: Policy.eq(Entity.ref("Document", "")) }),
    ];
    const decision = Policy.decidePure(
      policies,
      Policy.request({ principal: alice, action: read, resource: doc }),
      Entity.slice([member]),
    );
    expect(decision.allowed).toBe(false);
  });
});

describe("Policy.decide and enforce refuse an empty entity id (#661)", () => {
  it("does not run a custom permit's predicate for an empty-id principal", () => {
    let ran = false;
    const custom = Policy.custom({
      id: "custom",
      effect: "permit",
      predicate: () => Effect.sync(() => ((ran = true), true)),
    });
    const request = Policy.request({ principal: nobody, action: read, resource: doc });
    const decision = Effect.runSync(Policy.decide([custom], request));
    expect(decision).toMatchObject({ allowed: false, reason: "invalid-request" });
    expect(ran).toBe(false);
  });

  it("enforce fails with the invalid-request decision", () => {
    const request = Policy.request({ principal: nobody, action: read, resource: doc });
    const exit = Effect.runSyncExit(Policy.enforce([Policy.permit({ id: "all" })], request));
    assert(Exit.isFailure(exit));
    expect(String(exit.cause)).toContain("invalid-request");
  });
});

describe("ReadScope.compile refuses an empty entity id (#661)", () => {
  it("an empty-id principal's scope does not admit an empty-owner row", () => {
    const scope = compiled([ownerPermit], nobody);
    expect(scope).toEqual(ReadScope.deny);
    expect(ReadScope.matches(scope, { owner: "" })).toBe(false);
  });

  it("an empty-id principal's scope admits nothing under a type-scoped permit", () => {
    const anyUser = Policy.permit({ id: "any-user", principal: Policy.isType("User") });
    expect(compiled([anyUser], alice)).toEqual(ReadScope.allowAll);
    expect(compiled([anyUser], nobody)).toEqual(ReadScope.deny);
  });

  it("an empty-id literal does not compile to an empty-owner filter", () => {
    const literal = Policy.permit({
      id: "literal",
      when: Condition.eq(
        Condition.attr("resource", "owner"),
        Condition.lit(Entity.entityValue(nobody)),
      ),
    });
    const scope = compiled([literal], alice);
    expect(ReadScope.matches(scope, { owner: "" })).toBe(false);
    // The kernel agrees on that row.
    expect(decide([literal], { principal: alice }).allowed).toBe(false);
  });

  it("a non-empty principal still owns its own rows, and not the empty-owner ones", () => {
    const scope = compiled([ownerPermit], alice);
    expect(ReadScope.matches(scope, { owner: "alice" })).toBe(true);
    expect(ReadScope.matches(scope, { owner: "" })).toBe(false);
    expect(decide([ownerPermit], { principal: alice }).allowed).toBe(false);
  });
});

describe("Entity: an empty id names no entity (#661)", () => {
  it("equals nothing, itself included", () => {
    expect(Entity.refEquals(nobody, Entity.ref("User", ""))).toBe(false);
    expect(Entity.refEquals(alice, Entity.ref("User", "alice"))).toBe(true);
    const hollow = Entity.entityValue(nobody);
    expect(Entity.attributeValueEquals(hollow, Entity.entityValue(Entity.ref("User", "")))).toBe(
      false,
    );
    expect(Entity.attributeValueEquals([hollow], [hollow])).toBe(false);
    expect(Entity.attributeValueEquals({ owner: hollow }, { owner: hollow })).toBe(false);
  });

  it("is refused when decoded", () => {
    const decode = Schema.decodeExit(Entity.EntityRef);
    expect(Exit.isFailure(decode({ type: "User", id: "" }))).toBe(true);
    expect(Exit.isSuccess(decode({ type: "User", id: "alice" }))).toBe(true);
    expect(
      Exit.isFailure(
        Schema.decodeExit(Policy.PolicyRequest)({
          principal: { type: "User", id: "" },
          action: read,
          resource: doc,
          context: {},
        }),
      ),
    ).toBe(true);
  });
});

describe("Guard reads an empty-id viewer as anonymous (#661)", () => {
  interface AppUser {
    readonly id: string;
    readonly role: string;
  }
  class CurrentViewer extends Context.Service<CurrentViewer, Option.Option<AppUser>>()(
    "@test/EmptyEntityId/CurrentViewer",
  ) {}
  const Roles = Ladder.make(["user", "admin"]);
  const guards = Guard.make({ ladder: Roles, viewer: CurrentViewer });
  const owned = OwnedAccess.make({ guards, viewPrivate: Roles.axes({ all: "admin" }).all });
  const hollow: AppUser = { id: "", role: "admin" };
  const asHollow = SessionContext.viewerLayer(CurrentViewer, hollow);
  const run = <A>(effect: Effect.Effect<A, never, CurrentViewer>): A =>
    Effect.runSync(effect.pipe(Effect.provide(asHollow)));

  it("has no viewer, so no gate passes", () => {
    expect(run(guards.viewer)).toEqual(Option.none());
    const exit = Effect.runSyncExit(guards.requireUser.pipe(Effect.provide(asHollow)));
    expect(Exit.isFailure(exit)).toBe(true);
  });

  it("owns no empty-owner row and gets only the public scope", () => {
    expect(run(owned.canView({ ownerId: "", visibility: "private" }))).toBe(false);
    expect(run(owned.canView({ ownerId: "", visibility: "public" }))).toBe(true);
    expect(run(owned.readScope)).toEqual({ kind: "public" });
    expect(guards.decideOwnerOrRole(hollow, "", "admin")).toBe(false);
  });
});
