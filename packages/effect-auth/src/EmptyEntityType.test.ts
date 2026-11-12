/**
 * An empty entity type names no entity (#666), as an empty id does (#661).
 *
 * `Entity.ref("", "alice")` used to be an ordinary reference: it decoded, it
 * equalled itself, and a permit scoped to the type `""` (or a policy over an
 * attribute bound to that type) matched it. Both the kernel
 * (`Policy.decidePure`) and the compiled read scope (`ReadScope.compile`) now
 * refuse a request that names an empty type, and an empty-type reference
 * equals nothing, itself included.
 */
import { assert, describe, expect, it } from "vite-plus/test";
import { Effect, Exit } from "effect";
import * as P from "effect/Predicate";
import * as Schema from "effect/Schema";
import * as Condition from "./Condition.ts";
import * as Entity from "./Entity.ts";
import * as Policy from "./Policy.ts";
import * as ReadScope from "./ReadScope.ts";

const untyped = Entity.ref("", "alice");
const alice = Entity.ref("User", "alice");
const read = Entity.ref("Action", "read");
const doc = Entity.ref("Document", "doc-1");

/** The owner may read. */
const ownerPermit = Policy.permit({
  id: "owner",
  when: Condition.eq(Condition.attr("resource", "owner"), Condition.principal),
});
/** A binding whose owner column holds references of the empty type. */
const untypedBinding: ReadScope.Binding = {
  resourceType: "Document",
  attributes: { owner: { entity: "" } },
};

const ownedBy = (owner: Entity.EntityRef): Entity.Entity =>
  Entity.entity(doc, { attributes: { owner: Entity.entityValue(owner) } });

const decide = (
  policies: ReadonlyArray<Policy.DeclarativePolicy>,
  request: { readonly principal: Entity.EntityRef; readonly resource?: Entity.Entity },
  action: Entity.EntityRef = read,
): Policy.Decision => {
  const resource = request.resource ?? ownedBy(untyped);
  return Policy.decidePure(
    policies,
    Policy.request({ principal: request.principal, action, resource: resource.ref }),
    Entity.slice([resource]),
  );
};

const compiled = (
  policies: ReadonlyArray<Policy.DeclarativePolicy>,
  principal: Entity.EntityRef,
  binding: ReadScope.Binding = untypedBinding,
  action: Entity.EntityRef = read,
): ReadScope.ReadScope => {
  const result = ReadScope.compile(policies, binding, { principal, action });
  assert(P.isTagged(result, "Exact"), "the policy set compiles exactly");
  return result.scope;
};

describe("Policy.decidePure refuses an empty entity type (#666)", () => {
  it("an empty-type principal does not own a row whose owner has the empty type", () => {
    const decision = decide([ownerPermit], { principal: untyped });
    expect(decision.allowed).toBe(false);
    expect(decision.reason).toBe("invalid-request");
    expect(decision.determining).toEqual([]);
  });

  it("a permit scoped to the empty type never matches", () => {
    const emptyType = Policy.permit({ id: "empty-type", principal: Policy.isType("") });
    const decision = decide([emptyType], { principal: untyped });
    expect(decision).toMatchObject({ allowed: false, reason: "invalid-request" });
    const anyone = Policy.permit({ id: "anyone" });
    expect(decide([anyone], { principal: untyped }).reason).toBe("invalid-request");
  });

  it("an empty-type action or resource is refused as well", () => {
    const everything = Policy.permit({ id: "everything" });
    expect(decide([everything], { principal: alice }, Entity.ref("", "read")).reason).toBe(
      "invalid-request",
    );
    const unnamed = Entity.entity(Entity.ref("", "doc-1"));
    expect(decide([everything], { principal: alice, resource: unnamed }).reason).toBe(
      "invalid-request",
    );
    expect(decide([everything], { principal: alice, resource: ownedBy(alice) }).allowed).toBe(true);
  });

  it("isWellFormed checks the type of every entity in the request", () => {
    const wellFormed = Policy.request({ principal: alice, action: read, resource: doc });
    expect(Policy.isWellFormed(wellFormed)).toBe(true);
    expect(Policy.isWellFormed({ ...wellFormed, principal: untyped })).toBe(false);
    expect(Policy.isWellFormed({ ...wellFormed, action: Entity.ref("", "read") })).toBe(false);
    expect(Policy.isWellFormed({ ...wellFormed, resource: Entity.ref("", "doc-1") })).toBe(false);
  });

  it("an empty-type literal never equals an empty-type owner attribute", () => {
    const literal = Policy.permit({
      id: "literal",
      when: Condition.eq(
        Condition.attr("resource", "owner"),
        Condition.lit(Entity.entityValue(untyped)),
      ),
    });
    expect(decide([literal], { principal: alice }).allowed).toBe(false);
  });

  it("a scope naming an empty-type entity matches nothing, its own ref included", () => {
    const hollowRole = Entity.ref("", "admin");
    const member = Entity.entity(alice, { parents: [hollowRole] });
    const policies = [
      Policy.permit({ id: "in", principal: Policy.inScope(hollowRole) }),
      Policy.permit({ id: "eq", resource: Policy.eq(Entity.ref("", "doc-1")) }),
    ];
    const decision = Policy.decidePure(
      policies,
      Policy.request({ principal: alice, action: read, resource: doc }),
      Entity.slice([member]),
    );
    expect(decision.allowed).toBe(false);
  });
});

describe("Policy.decide and enforce refuse an empty entity type (#666)", () => {
  it("does not run a custom permit's predicate for an empty-type principal", () => {
    let ran = false;
    const custom = Policy.custom({
      id: "custom",
      effect: "permit",
      predicate: () => Effect.sync(() => ((ran = true), true)),
    });
    const request = Policy.request({ principal: untyped, action: read, resource: doc });
    const decision = Effect.runSync(Policy.decide([custom], request));
    expect(decision).toMatchObject({ allowed: false, reason: "invalid-request" });
    expect(ran).toBe(false);
  });

  it("enforce fails with the invalid-request decision", () => {
    const request = Policy.request({ principal: untyped, action: read, resource: doc });
    const exit = Effect.runSyncExit(Policy.enforce([Policy.permit({ id: "all" })], request));
    assert(Exit.isFailure(exit));
    expect(String(exit.cause)).toContain("invalid-request");
  });
});

describe("ReadScope.compile refuses an empty entity type (#666)", () => {
  it("an empty-type principal's scope does not admit the rows it would own", () => {
    const scope = compiled([ownerPermit], untyped);
    expect(scope).toEqual(ReadScope.deny);
    expect(ReadScope.matches(scope, { owner: "alice" })).toBe(false);
  });

  it("an empty-type principal or action admits nothing, even under an unscoped permit", () => {
    const anyone = Policy.permit({ id: "anyone" });
    const typed: ReadScope.Binding = { resourceType: "Document", attributes: {} };
    expect(compiled([anyone], alice, typed)).toEqual(ReadScope.allowAll);
    expect(compiled([anyone], untyped, typed)).toEqual(ReadScope.deny);
    expect(compiled([anyone], alice, typed, Entity.ref("", "read"))).toEqual(ReadScope.deny);
  });

  it("a permit scoped to the empty type admits nothing", () => {
    const emptyType = Policy.permit({ id: "empty-type", principal: Policy.isType("") });
    expect(compiled([emptyType], untyped)).toEqual(ReadScope.deny);
    expect(compiled([emptyType], alice)).toEqual(ReadScope.deny);
  });

  it("an empty-type literal does not compile to an owner filter", () => {
    const literal = Policy.permit({
      id: "literal",
      when: Condition.eq(
        Condition.attr("resource", "owner"),
        Condition.lit(Entity.entityValue(untyped)),
      ),
    });
    const scope = compiled([literal], alice);
    expect(scope).toEqual(ReadScope.deny);
    expect(ReadScope.matches(scope, { owner: "alice" })).toBe(false);
    // The kernel agrees on that row.
    expect(decide([literal], { principal: alice }).allowed).toBe(false);
  });

  it("a rows-of-the-empty-type binding admits nothing, as the kernel refuses each row", () => {
    const anyone = Policy.permit({ id: "anyone" });
    const binding: ReadScope.Binding = { resourceType: "", attributes: {} };
    expect(compiled([anyone], alice, binding)).toEqual(ReadScope.deny);
    const row = Entity.entity(Entity.ref("", "row-1"));
    expect(decide([anyone], { principal: alice, resource: row }).allowed).toBe(false);
  });
});

describe("Entity: an empty type names no entity (#666)", () => {
  it("namesEntity checks the type and the id", () => {
    expect(Entity.namesEntity(alice)).toBe(true);
    expect(Entity.namesEntity(untyped)).toBe(false);
    expect(Entity.namesEntity(Entity.ref("User", ""))).toBe(false);
    expect(Entity.namesEntity(Entity.ref("", ""))).toBe(false);
  });

  it("equals nothing, itself included", () => {
    expect(Entity.refEquals(untyped, Entity.ref("", "alice"))).toBe(false);
    expect(Entity.refEquals(untyped, untyped)).toBe(false);
    const hollow = Entity.entityValue(untyped);
    expect(Entity.attributeValueEquals(hollow, Entity.entityValue(Entity.ref("", "alice")))).toBe(
      false,
    );
    expect(Entity.attributeValueEquals([hollow], [hollow])).toBe(false);
    expect(Entity.attributeValueEquals({ owner: hollow }, { owner: hollow })).toBe(false);
  });

  it("is in nothing, and nothing is in it", () => {
    const hollowRole = Entity.ref("", "admin");
    const slice = Entity.slice([Entity.entity(alice, { parents: [hollowRole] })]);
    expect(Entity.entityIn(slice, alice, hollowRole)).toBe(false);
    expect(Entity.entityIn(slice, untyped, untyped)).toBe(false);
  });

  it("is refused when decoded", () => {
    const decode = Schema.decodeExit(Entity.EntityRef);
    expect(Exit.isFailure(decode({ type: "", id: "alice" }))).toBe(true);
    expect(Exit.isSuccess(decode({ type: "User", id: "alice" }))).toBe(true);
    expect(
      Exit.isFailure(
        Schema.decodeExit(Policy.PolicyRequest)({
          principal: { type: "", id: "alice" },
          action: read,
          resource: doc,
          context: {},
        }),
      ),
    ).toBe(true);
  });
});
