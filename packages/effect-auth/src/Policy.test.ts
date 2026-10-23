import { describe, it, expect } from "vite-plus/test";
import { Array as Arr, Effect, Schema } from "effect";
import * as Entity from "./Entity.ts";
import * as Condition from "./Condition.ts";
import * as Policy from "./Policy.ts";
import * as Errors from "./Errors.ts";

const alice = Entity.ref("User", "alice");
const bob = Entity.ref("User", "bob");
const readDoc = Entity.ref("Action", "doc:read");
const deleteDoc = Entity.ref("Action", "doc:delete");
const doc1 = Entity.ref("Document", "doc-1");

const requestFor = (
  principal: Entity.EntityRef,
  action: Entity.EntityRef,
  resource: Entity.EntityRef,
  context: Record<string, Entity.AttributeValue> = {},
): Policy.PolicyRequest => Policy.request({ principal, action, resource, context });

describe("Entity slices", () => {
  it("entityIn is reflexive and transitive over the parent DAG", () => {
    const s = Entity.slice([
      Entity.entity(alice, { parents: [Entity.ref("Team", "eng")] }),
      Entity.entity(Entity.ref("Team", "eng"), { parents: [Entity.ref("Org", "acme")] }),
    ]);
    expect(Entity.entityIn(s, alice, alice)).toBe(true);
    expect(Entity.entityIn(s, alice, Entity.ref("Team", "eng"))).toBe(true);
    expect(Entity.entityIn(s, alice, Entity.ref("Org", "acme"))).toBe(true);
    expect(Entity.entityIn(s, alice, Entity.ref("Org", "other"))).toBe(false);
    // Unknown entities have no ancestors but remain reflexively `in` themselves.
    expect(Entity.entityIn(s, bob, bob)).toBe(true);
    expect(Entity.entityIn(s, bob, Entity.ref("Org", "acme"))).toBe(false);
  });

  it("entityIn terminates on a cyclic hierarchy", () => {
    const a = Entity.ref("Group", "a");
    const b = Entity.ref("Group", "b");
    const s = Entity.slice([
      Entity.entity(a, { parents: [b] }),
      Entity.entity(b, { parents: [a] }),
    ]);
    expect(Entity.entityIn(s, a, b)).toBe(true);
    expect(Entity.entityIn(s, a, Entity.ref("Group", "c"))).toBe(false);
  });
});

describe("decidePure semantics", () => {
  it("denies by default with no policies", () => {
    const decision = Policy.decidePure([], requestFor(alice, readDoc, doc1));
    expect(decision.allowed).toBe(false);
    expect(decision.reason).toBe("default-deny");
    expect(decision.determining).toHaveLength(0);
  });

  it("a matching permit allows and appears as determining", () => {
    const permit = Policy.permit({ id: "p1", action: Policy.eq(readDoc) });
    const decision = Policy.decidePure([permit], requestFor(alice, readDoc, doc1));
    expect(decision.allowed).toBe(true);
    expect(decision.reason).toBe("permit");
    expect(decision.determining.map((o) => o.policyId)).toEqual(["p1"]);
  });

  it("a non-matching permit leaves the default deny", () => {
    const permit = Policy.permit({ id: "p1", action: Policy.eq(deleteDoc) });
    const decision = Policy.decidePure([permit], requestFor(alice, readDoc, doc1));
    expect(decision.allowed).toBe(false);
    expect(decision.outcomes[0]?.result).toBe("not-matched");
  });

  it("forbid overrides permit regardless of order", () => {
    const permit = Policy.permit({ id: "allow-all" });
    const forbid = Policy.forbid({ id: "deny-bob", principal: Policy.eq(bob) });
    Arr.forEach(
      [
        [permit, forbid],
        [forbid, permit],
      ],
      (policies) => {
        const decision = Policy.decidePure(policies, requestFor(bob, readDoc, doc1));
        expect(decision.allowed).toBe(false);
        expect(decision.reason).toBe("forbid");
        expect(decision.determining.map((o) => o.policyId)).toEqual(["deny-bob"]);
      },
    );
    // Alice is not covered by the forbid.
    expect(Policy.decidePure([permit, forbid], requestFor(alice, readDoc, doc1)).allowed).toBe(
      true,
    );
  });

  it("scope matching: is-type and in-hierarchy", () => {
    const s = Entity.slice([Entity.entity(alice, { parents: [Entity.ref("Role", "admin")] })]);
    const adminPolicy = Policy.role("admin", { resource: Policy.isType("Document") });
    expect(Policy.decidePure([adminPolicy], requestFor(alice, readDoc, doc1), s).allowed).toBe(
      true,
    );
    // Bob is not in Role::"admin"; a User-typed resource also fails the is-scope.
    expect(Policy.decidePure([adminPolicy], requestFor(bob, readDoc, doc1), s).allowed).toBe(false);
    expect(Policy.decidePure([adminPolicy], requestFor(alice, readDoc, bob), s).allowed).toBe(
      false,
    );
  });

  it("ownership via conditions: resource.owner == principal", () => {
    const s = Entity.slice([
      Entity.entity(doc1, { attributes: { owner: Entity.entityValue(alice) } }),
    ]);
    const owner = Policy.permit({
      id: "owner-can-read",
      action: Policy.eq(readDoc),
      when: Condition.eq(Condition.attr("resource", "owner"), Condition.principal),
    });
    expect(Policy.decidePure([owner], requestFor(alice, readDoc, doc1), s).allowed).toBe(true);
    expect(Policy.decidePure([owner], requestFor(bob, readDoc, doc1), s).allowed).toBe(false);
  });

  it("conditions: numeric comparison, contains, has, context", () => {
    const s = Entity.slice([
      Entity.entity(doc1, {
        attributes: { sensitivity: 3, tags: ["public", "docs"] },
      }),
    ]);
    const policy = Policy.permit({
      id: "p",
      when: Condition.and(
        Condition.lte(Condition.attr("resource", "sensitivity"), Condition.lit(5)),
        Condition.contains(Condition.attr("resource", "tags"), Condition.lit("public")),
        Condition.has("resource", "tags"),
        Condition.eq(Condition.attr("context", "mfa"), Condition.lit(true)),
      ),
    });
    expect(
      Policy.decidePure([policy], requestFor(alice, readDoc, doc1, { mfa: true }), s).allowed,
    ).toBe(true);
    expect(
      Policy.decidePure([policy], requestFor(alice, readDoc, doc1, { mfa: false }), s).allowed,
    ).toBe(false);
  });
});

describe("fail-closed error semantics", () => {
  const badCondition = Condition.gt(Condition.attr("resource", "missing"), Condition.lit(1));

  it("an erroring permit cannot grant", () => {
    const permit = Policy.permit({ id: "err-permit", when: badCondition });
    const decision = Policy.decidePure([permit], requestFor(alice, readDoc, doc1));
    expect(decision.allowed).toBe(false);
    expect(decision.reason).toBe("default-deny");
    expect(decision.outcomes[0]?.result).toBe("error");
  });

  it("an erroring forbid DENIES even when a permit matches", () => {
    const permit = Policy.permit({ id: "allow-all" });
    const forbid = Policy.forbid({ id: "err-forbid", when: badCondition });
    const decision = Policy.decidePure([permit, forbid], requestFor(alice, readDoc, doc1));
    expect(decision.allowed).toBe(false);
    expect(decision.reason).toBe("forbid");
    expect(decision.determining.map((o) => o.policyId)).toEqual(["err-forbid"]);
    expect(decision.determining[0]?.result).toBe("error");
  });

  it("and/or short-circuit around errors like Cedar's operators", () => {
    const request = requestFor(alice, readDoc, doc1, { flag: false });
    const falseFirst = Condition.and(
      Condition.eq(Condition.attr("context", "flag"), Condition.lit(true)),
      badCondition,
    );
    const trueFirst = Condition.or(
      Condition.eq(Condition.attr("context", "flag"), Condition.lit(false)),
      badCondition,
    );
    expect(Condition.evaluate(Entity.emptySlice, request, falseFirst)).toEqual({
      ok: true,
      value: false,
    });
    expect(Condition.evaluate(Entity.emptySlice, request, trueFirst)).toEqual({
      ok: true,
      value: true,
    });
  });

  describe("isIn", () => {
    const eng = Entity.ref("Team", "eng");
    const acme = Entity.ref("Org", "acme");
    const s = Entity.slice([
      Entity.entity(alice, { parents: [eng] }),
      Entity.entity(eng, { parents: [acme] }),
    ]);
    const request = requestFor(alice, readDoc, doc1, { label: "x" });

    it("is true when the left entity descends from the right one", () => {
      const condition = Condition.isIn(Condition.principal, Condition.entityLit(acme));
      expect(Condition.evaluate(s, request, condition)).toEqual({ ok: true, value: true });
    });

    it("is false when the left entity is outside the right one", () => {
      const condition = Condition.isIn(
        Condition.principal,
        Condition.entityLit(Entity.ref("Org", "other")),
      );
      expect(Condition.evaluate(s, request, condition)).toEqual({ ok: true, value: false });
    });

    it("errors when either operand is not an entity", () => {
      expect(
        Condition.evaluate(s, request, Condition.isIn(Condition.principal, Condition.lit("acme"))),
      ).toEqual({ ok: false, error: { message: "in requires entity operands" } });
      expect(
        Condition.evaluate(s, request, Condition.isIn(Condition.lit(1), Condition.entityLit(acme))),
      ).toEqual({ ok: false, error: { message: "in requires entity operands" } });
    });

    it("propagates an operand's evaluation error", () => {
      const missingLeft = Condition.isIn(
        Condition.attr("context", "missing"),
        Condition.entityLit(acme),
      );
      const missingRight = Condition.isIn(
        Condition.principal,
        Condition.attr("context", "missing"),
      );
      expect(Condition.evaluate(s, request, missingLeft)).toEqual({
        ok: false,
        error: { message: 'attribute "context.missing" is absent' },
      });
      expect(Condition.evaluate(s, request, missingRight)).toEqual({
        ok: false,
        error: { message: 'attribute "context.missing" is absent' },
      });
    });
  });
});

describe("custom policies", () => {
  it("participates in decisions and carries its requirements", async () => {
    const evenMinute = Policy.custom({
      id: "custom-ok",
      predicate: (req) => Effect.succeed(req.principal.id === "alice"),
    });
    const decision = await Effect.runPromise(
      Policy.decide([evenMinute], requestFor(alice, readDoc, doc1)),
    );
    expect(decision.allowed).toBe(true);
    expect(decision.determining[0]?.policyId).toBe("custom-ok");
  });

  it("a failing custom permit cannot grant; a failing custom forbid denies", async () => {
    const failing = (id: string, effect: Policy.PolicyEffect) =>
      Policy.custom({
        id,
        effect,
        predicate: () => Effect.fail(new Errors.AuthError({ message: "store down" })),
      });
    const denied = await Effect.runPromise(
      Policy.decide([failing("p", "permit")], requestFor(alice, readDoc, doc1)),
    );
    expect(denied.allowed).toBe(false);
    expect(denied.outcomes[0]?.result).toBe("error");

    const overridden = await Effect.runPromise(
      Policy.decide(
        [Policy.permit({ id: "allow-all" }), failing("f", "forbid")],
        requestFor(alice, readDoc, doc1),
      ),
    );
    expect(overridden.allowed).toBe(false);
    expect(overridden.reason).toBe("forbid");
  });
});

describe("enforce and check", () => {
  it("enforce fails with AuthorizationDeniedError carrying the trace", async () => {
    const forbid = Policy.forbid({ id: "deny-delete", action: Policy.eq(deleteDoc) });
    const error = await Effect.runPromise(
      Effect.flip(Policy.enforce([forbid], requestFor(alice, deleteDoc, doc1))),
    );
    expect(error._tag).toBe("AuthorizationDeniedError");
    expect(error.decision.reason).toBe("forbid");
    expect(error.request.principal).toEqual(alice);
    expect(error.message).toContain('User::"alice"');
  });

  it("enforce succeeds with the decision when allowed", async () => {
    const decision = await Effect.runPromise(
      Policy.enforce([Policy.permit({ id: "allow-all" })], requestFor(alice, readDoc, doc1)),
    );
    expect(decision.allowed).toBe(true);
  });

  it("check returns a plain boolean", async () => {
    expect(await Effect.runPromise(Policy.check([], requestFor(alice, readDoc, doc1)))).toBe(false);
  });
});

describe("constructors", () => {
  it("permission bridges PermissionRef semantics including wildcards", () => {
    const posts = Policy.permission({ resource: "Document", action: "doc:read" });
    expect(Policy.decidePure([posts], requestFor(alice, readDoc, doc1)).allowed).toBe(true);
    expect(Policy.decidePure([posts], requestFor(alice, deleteDoc, doc1)).allowed).toBe(false);

    const superuser = Policy.permission({ resource: "*", action: "*" });
    expect(Policy.decidePure([superuser], requestFor(alice, deleteDoc, bob)).allowed).toBe(true);
  });

  it("action narrows to one named action", () => {
    const policy = Policy.action("doc:read");
    expect(Policy.decidePure([policy], requestFor(alice, readDoc, doc1)).allowed).toBe(true);
    expect(Policy.decidePure([policy], requestFor(alice, deleteDoc, doc1)).allowed).toBe(false);
  });

  it("when ANDs additional conditions onto a policy", () => {
    const base = Policy.permit({ id: "p" });
    const gated = Policy.when(
      Policy.when(base, Condition.eq(Condition.attr("context", "a"), Condition.lit(1))),
      Condition.eq(Condition.attr("context", "b"), Condition.lit(2)),
    );
    expect(
      Policy.decidePure([gated], requestFor(alice, readDoc, doc1, { a: 1, b: 2 })).allowed,
    ).toBe(true);
    expect(
      Policy.decidePure([gated], requestFor(alice, readDoc, doc1, { a: 1, b: 3 })).allowed,
    ).toBe(false);
  });
});

describe("declarative policies are data", () => {
  it("roundtrips through Schema encode/decode as JSON", async () => {
    const policy = Policy.permit({
      id: "doc-owner-read",
      principal: Policy.isType("User"),
      action: Policy.eq(readDoc),
      resource: Policy.isType("Document"),
      when: Condition.and(
        Condition.eq(Condition.attr("resource", "owner"), Condition.principal),
        Condition.gte(Condition.attr("context", "assurance"), Condition.lit(2)),
      ),
      description: "Owners may read their documents",
    });

    const encoded = await Effect.runPromise(Schema.encodeEffect(Policy.DeclarativePolicy)(policy));
    const Json = Schema.fromJsonString(Schema.Unknown);
    const json = Schema.decodeUnknownSync(Json)(Schema.encodeSync(Json)(encoded));
    const decoded = await Effect.runPromise(
      Schema.decodeUnknownEffect(Policy.DeclarativePolicy)(json),
    );
    expect(decoded).toEqual(policy);

    // The decoded document decides identically (replayability).
    const s = Entity.slice([
      Entity.entity(doc1, { attributes: { owner: Entity.entityValue(alice) } }),
    ]);
    const req = requestFor(alice, readDoc, doc1, { assurance: 2 });
    expect(Policy.decidePure([decoded], req, s)).toEqual(Policy.decidePure([policy], req, s));
  });

  it("rejects malformed documents", async () => {
    const result = await Effect.runPromise(
      Effect.result(
        Schema.decodeUnknownEffect(Policy.DeclarativePolicy)({
          _tag: "DeclarativePolicy",
          id: "x",
          effect: "grant", // invalid
          principal: { _tag: "any" },
          action: { _tag: "any" },
          resource: { _tag: "any" },
        }),
      ),
    );
    expect(result._tag).toBe("Failure");
  });
});
