import { describe, it, expect } from "vite-plus/test";
import { Effect, Layer } from "effect";
import * as Entity from "./Entity.ts";
import * as Condition from "./Condition.ts";
import * as Policy from "./Policy.ts";
import * as Model from "./Model.ts";
import * as Authorizer from "./Authorizer.ts";

const alice = Entity.ref("User", "alice");
const bob = Entity.ref("User", "bob");
const readDoc = Entity.ref("Action", "doc:read");
const deleteDoc = Entity.ref("Action", "doc:delete");
const doc1 = Entity.ref("Document", "doc-1");

// ---------------------------------------------------------------------------
// memoryEntityResolver
// ---------------------------------------------------------------------------

describe("memoryEntityResolver", () => {
  it("returns requested entities plus their transitive ancestors", async () => {
    const team = Entity.ref("Team", "eng");
    const org = Entity.ref("Org", "acme");
    const resolver = Authorizer.memoryEntityResolver([
      Entity.entity(alice, { parents: [team] }),
      Entity.entity(team, { parents: [org] }),
      Entity.entity(org),
    ]);
    const result = await Effect.runPromise(resolver.resolve([alice]));
    const refs = result.map((e) => e.ref);
    expect(refs).toContainEqual(alice);
    expect(refs).toContainEqual(team);
    expect(refs).toContainEqual(org);
    expect(result).toHaveLength(3);
  });

  it("omits unknown refs", async () => {
    const resolver = Authorizer.memoryEntityResolver([Entity.entity(alice)]);
    const result = await Effect.runPromise(resolver.resolve([alice, bob]));
    expect(result.map((e) => e.ref)).toEqual([alice]);
  });

  it("handles a cyclic parent hierarchy without hanging", async () => {
    const a = Entity.ref("Group", "a");
    const b = Entity.ref("Group", "b");
    const resolver = Authorizer.memoryEntityResolver([
      Entity.entity(a, { parents: [b] }),
      Entity.entity(b, { parents: [a] }),
    ]);
    const result = await Effect.runPromise(resolver.resolve([a]));
    expect(result.map((e) => e.ref).sort((x, y) => x.id.localeCompare(y.id))).toEqual([a, b]);
  });
});

// ---------------------------------------------------------------------------
// requestRefs
// ---------------------------------------------------------------------------

describe("requestRefs", () => {
  it("collects principal/action/resource plus eq/in scope refs and condition literals, deduplicated", () => {
    const owner = Entity.ref("User", "owner");
    const team = Entity.ref("Team", "eng");
    const policies: ReadonlyArray<Policy.Policy> = [
      Policy.permit({
        id: "p1",
        principal: Policy.inScope(team),
        action: Policy.eq(readDoc),
        resource: Policy.eq(doc1), // duplicate of request.resource
        when: Condition.eq(Condition.attr("resource", "owner"), Condition.entityLit(owner)),
      }),
      Policy.permit({ id: "p2", principal: Policy.any }), // any scope contributes nothing
    ];
    const request = Policy.request({ principal: alice, action: readDoc, resource: doc1 });
    const refs = Authorizer.requestRefs(policies, request);

    expect(refs).toContainEqual(alice);
    expect(refs).toContainEqual(readDoc);
    expect(refs).toContainEqual(doc1);
    expect(refs).toContainEqual(team);
    expect(refs).toContainEqual(owner);

    // Deduplicated: doc1 appears both as request.resource and the eq scope ref.
    const keys = refs.map(Entity.refKey);
    expect(new Set(keys).size).toBe(keys.length);
    expect(refs).toHaveLength(5);
  });

  it("ignores custom policies (no scopes to inspect)", () => {
    const custom = Policy.custom({
      id: "c1",
      predicate: () => Effect.succeed(true),
    });
    const request = Policy.request({ principal: alice, action: readDoc, resource: doc1 });
    const refs = Authorizer.requestRefs([custom], request);
    expect(refs).toEqual([alice, readDoc, doc1]);
  });
});

// ---------------------------------------------------------------------------
// The Authorizer service
// ---------------------------------------------------------------------------

describe("Authorizer", () => {
  const ownerPolicy = Policy.permit({
    id: "owner-can-read",
    action: Policy.eq(readDoc),
    when: Condition.eq(Condition.attr("resource", "owner"), Condition.principal),
  });

  it("authorize succeeds for an owner policy resolved through the resolver", async () => {
    const resolver = Authorizer.memoryEntityResolver([
      Entity.entity(doc1, { attributes: { owner: Entity.entityValue(alice) } }),
    ]);
    const layer = Authorizer.Authorizer.layer({ policies: [ownerPolicy] }).pipe(
      Layer.provide(Layer.succeed(Authorizer.EntityResolver)(resolver)),
    );
    const program = Authorizer.Authorizer.pipe(
      Effect.flatMap((authz) => authz.authorize({ action: readDoc, resource: doc1 })),
      Authorizer.CurrentPrincipal.provide(alice),
    );
    const decision = await Effect.runPromise(Effect.provide(program, layer));
    expect(decision.allowed).toBe(true);
  });

  it("authorize fails with AuthorizationDeniedError carrying the decision trace on default deny", async () => {
    const layer = Authorizer.Authorizer.layer({ policies: [] });
    const program = Authorizer.Authorizer.pipe(
      Effect.flatMap((authz) => authz.authorize({ action: readDoc, resource: doc1 })),
      Authorizer.CurrentPrincipal.provide(bob),
    );
    const error = await Effect.runPromise(Effect.provide(program, layer).pipe(Effect.flip));
    expect(error._tag).toBe("AuthorizationDeniedError");
    expect(error.decision.reason).toBe("default-deny");
    expect(error.decision.allowed).toBe(false);
  });

  it("check returns booleans without failing", async () => {
    const resolver = Authorizer.memoryEntityResolver([
      Entity.entity(doc1, { attributes: { owner: Entity.entityValue(alice) } }),
    ]);
    const layer = Authorizer.Authorizer.layer({ policies: [ownerPolicy] }).pipe(
      Layer.provide(Layer.succeed(Authorizer.EntityResolver)(resolver)),
    );
    const program = Effect.gen(function* () {
      const authz = yield* Authorizer.Authorizer;
      const allowed = yield* authz
        .check({ action: readDoc, resource: doc1 })
        .pipe(Authorizer.CurrentPrincipal.provide(alice));
      const denied = yield* authz
        .check({ action: readDoc, resource: doc1 })
        .pipe(Authorizer.CurrentPrincipal.provide(bob));
      return { allowed, denied };
    });
    const result = await Effect.runPromise(Effect.provide(program, layer));
    expect(result.allowed).toBe(true);
    expect(result.denied).toBe(false);
  });

  it("decideRequest works with an explicit request, no CurrentPrincipal needed", async () => {
    const resolver = Authorizer.memoryEntityResolver([
      Entity.entity(doc1, { attributes: { owner: Entity.entityValue(alice) } }),
    ]);
    const layer = Authorizer.Authorizer.layer({ policies: [ownerPolicy] }).pipe(
      Layer.provide(Layer.succeed(Authorizer.EntityResolver)(resolver)),
    );
    const program = Authorizer.Authorizer.pipe(
      Effect.flatMap((authz) =>
        authz.decideRequest(Policy.request({ principal: alice, action: readDoc, resource: doc1 })),
      ),
    );
    const decision = await Effect.runPromise(Effect.provide(program, layer));
    expect(decision.allowed).toBe(true);
    expect(decision.reason).toBe("permit");
  });

  it("RBAC via the model + resolver: principal with Role::admin parent", async () => {
    const model: Model.Model = Model.make({
      entities: { User: {}, Document: {}, Role: {} },
      actions: {
        "doc:read": { appliesTo: { principal: ["User"], resource: ["Document"] } },
      },
    });
    const adminPolicy = Policy.role("admin", { resource: Policy.isType("Document") });
    const resolver = Authorizer.memoryEntityResolver([
      Entity.entity(alice, { parents: [Entity.ref("Role", "admin")] }),
    ]);
    const layer = Authorizer.Authorizer.layer({ policies: [adminPolicy], model }).pipe(
      Layer.provide(Layer.succeed(Authorizer.EntityResolver)(resolver)),
    );
    const program = Effect.gen(function* () {
      const authz = yield* Authorizer.Authorizer;
      const allowedForAdmin = yield* authz
        .check({ action: readDoc, resource: doc1 })
        .pipe(Authorizer.CurrentPrincipal.provide(alice));
      const deniedForNonAdmin = yield* authz
        .check({ action: readDoc, resource: doc1 })
        .pipe(Authorizer.CurrentPrincipal.provide(bob));
      return { allowedForAdmin, deniedForNonAdmin };
    });
    const result = await Effect.runPromise(Effect.provide(program, layer));
    expect(result.allowedForAdmin).toBe(true);
    expect(result.deniedForNonAdmin).toBe(false);
  });

  it("action groups: a member action is allowed via an in-scope group policy, without the resolver knowing about actions", async () => {
    const model: Model.Model = Model.make({
      entities: { User: {}, Document: {} },
      actions: {
        "doc:read": {
          appliesTo: { principal: ["User"], resource: ["Document"] },
          memberOf: ["doc:all"],
        },
      },
    });
    const groupPolicy = Policy.permit({
      id: "group-permit",
      action: Policy.inScope(Entity.ref("Action", "doc:all")),
    });
    // No resolver in context at all — model action entities are merged into every slice.
    const layer = Authorizer.Authorizer.layer({ policies: [groupPolicy], model });
    const program = Authorizer.Authorizer.pipe(
      Effect.flatMap((authz) => authz.check({ action: readDoc, resource: doc1 })),
      Authorizer.CurrentPrincipal.provide(alice),
    );
    const allowed = await Effect.runPromise(Effect.provide(program, layer));
    expect(allowed).toBe(true);
  });

  it("CurrentPrincipal.provide supplies the principal for authorize/check", async () => {
    const layer = Authorizer.Authorizer.layer({ policies: [Policy.permit({ id: "allow-all" })] });
    const program = Authorizer.Authorizer.pipe(
      Effect.flatMap((authz) => authz.check({ action: readDoc, resource: doc1 })),
    );
    const allowed = await Effect.runPromise(
      Effect.provide(program.pipe(Authorizer.CurrentPrincipal.provide(alice)), layer),
    );
    expect(allowed).toBe(true);
  });

  it("layer construction fails with PolicyValidationError when a policy names an undeclared entity type", async () => {
    const model: Model.Model = Model.make({
      entities: { User: {} },
      actions: {},
    });
    const badPolicy = Policy.permit({ id: "bad", principal: Policy.isType("Robot") });
    const layer = Authorizer.Authorizer.layer({ policies: [badPolicy], model });
    const program = Authorizer.Authorizer.pipe(
      Effect.flatMap((authz) => authz.check({ action: readDoc, resource: doc1 })),
      Authorizer.CurrentPrincipal.provide(alice),
    );
    const error = await Effect.runPromise(Effect.provide(program, layer).pipe(Effect.flip));
    // `PolicyValidationError` subclasses `Errors.AuthError` without
    // re-tagging, so `_tag` stays "AuthError" (uniform for the `AuthError`
    // error channel); the specific type is distinguished by `instanceof`.
    expect(error).toBeInstanceOf(Authorizer.PolicyValidationError);
    expect(error._tag).toBe("AuthError");
    expect(error.message).toContain("Robot");
  });

  it("without an EntityResolver, pure-context policies still work and hierarchy checks see no parents", async () => {
    const contextOnlyPermit = Policy.permit({
      id: "mfa-permit",
      when: Condition.eq(Condition.attr("context", "mfa"), Condition.lit(true)),
    });
    const layer = Authorizer.Authorizer.layer({ policies: [contextOnlyPermit] });
    const program = Effect.gen(function* () {
      const authz = yield* Authorizer.Authorizer;
      const allowed = yield* authz
        .check({ action: readDoc, resource: doc1, context: { mfa: true } })
        .pipe(Authorizer.CurrentPrincipal.provide(alice));
      const denied = yield* authz
        .check({ action: readDoc, resource: doc1, context: { mfa: false } })
        .pipe(Authorizer.CurrentPrincipal.provide(alice));
      return { allowed, denied };
    });
    const result = await Effect.runPromise(Effect.provide(program, layer));
    expect(result.allowed).toBe(true);
    expect(result.denied).toBe(false);

    // Hierarchy check with no resolver: no parents are ever seen, so an
    // `in`-scoped policy on a role never matches even reflexively for
    // another entity.
    const rolePolicy = Policy.role("admin");
    const roleLayer = Authorizer.Authorizer.layer({ policies: [rolePolicy] });
    const roleProgram = Authorizer.Authorizer.pipe(
      Effect.flatMap((authz) => authz.check({ action: readDoc, resource: doc1 })),
      Authorizer.CurrentPrincipal.provide(alice),
    );
    const roleAllowed = await Effect.runPromise(Effect.provide(roleProgram, roleLayer));
    expect(roleAllowed).toBe(false);
  });
});
