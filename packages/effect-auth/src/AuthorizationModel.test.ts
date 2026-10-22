import { describe, it, expect } from "vite-plus/test";
import { Array as Arr, Order } from "effect";
import * as Entity from "./Entity.ts";
import * as Condition from "./Condition.ts";
import * as Policy from "./Policy.ts";
import * as AuthorizationModel from "./AuthorizationModel.ts";

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

const alice = Entity.ref("User", "alice");

const baseModel: AuthorizationModel.Model = AuthorizationModel.make({
  entities: {
    User: {},
    Document: { memberOf: ["Folder"] },
    Folder: {},
  },
  actions: {
    "doc:read": { appliesTo: { principal: ["User"], resource: ["Document"] } },
    "doc:delete": {
      appliesTo: { principal: ["User"], resource: ["Document"] },
      memberOf: ["doc:all"],
    },
  },
});

describe("actionEntities", () => {
  it("turns declared actions into Action entities with memberOf as parents", () => {
    const entities = AuthorizationModel.actionEntities(baseModel);
    const read = entities.find((e) => Entity.refEquals(e.ref, Entity.ref("Action", "doc:read")));
    const del = entities.find((e) => Entity.refEquals(e.ref, Entity.ref("Action", "doc:delete")));
    expect(read).toBeDefined();
    expect(read?.parents).toEqual([]);
    expect(del).toBeDefined();
    expect(del?.parents).toEqual([Entity.ref("Action", "doc:all")]);
  });

  it("synthesizes group entities for groups that are not themselves declared actions", () => {
    const entities = AuthorizationModel.actionEntities(baseModel);
    const group = entities.find((e) => Entity.refEquals(e.ref, Entity.ref("Action", "doc:all")));
    expect(group).toBeDefined();
    expect(group?.parents).toEqual([]);
    // Exactly one entity for the group (not duplicated).
    expect(
      entities.filter((e) => Entity.refEquals(e.ref, Entity.ref("Action", "doc:all"))),
    ).toHaveLength(1);
  });

  it("does not duplicate a group that IS itself a declared action", () => {
    const model = AuthorizationModel.make({
      entities: {},
      actions: {
        "doc:all": { appliesTo: { principal: [], resource: [] } },
        "doc:read": {
          appliesTo: { principal: [], resource: [] },
          memberOf: ["doc:all"],
        },
      },
    });
    const entities = AuthorizationModel.actionEntities(model);
    const matches = entities.filter((e) =>
      Entity.refEquals(e.ref, Entity.ref("Action", "doc:all")),
    );
    expect(matches).toHaveLength(1);
    // It's the declared action entity (memberOf empty for doc:all itself).
    expect(matches[0]?.parents).toEqual([]);
    expect(entities).toHaveLength(2);
  });
});

describe("validatePolicies", () => {
  it("returns no issues for a well-formed policy set", () => {
    const policy = Policy.permit({
      id: "p1",
      principal: Policy.isType("User"),
      action: Policy.eq(Entity.ref("Action", "doc:read")),
      resource: Policy.isType("Document"),
    });
    expect(AuthorizationModel.validatePolicies(baseModel, [policy])).toEqual([]);
  });

  it("flags an undeclared entity type in an eq principal scope", () => {
    const policy = Policy.permit({
      id: "bad-principal-eq",
      principal: Policy.eq(Entity.ref("Robot", "r1")),
    });
    const issues = AuthorizationModel.validatePolicies(baseModel, [policy]);
    expect(issues).toHaveLength(1);
    expect(issues[0]?.policyId).toBe("bad-principal-eq");
    expect(issues[0]?.message).toContain("Robot");
  });

  it("flags an undeclared entity type in an in resource scope", () => {
    const policy = Policy.permit({
      id: "bad-resource-in",
      resource: Policy.inScope(Entity.ref("Robot", "r1")),
    });
    const issues = AuthorizationModel.validatePolicies(baseModel, [policy]);
    expect(issues).toHaveLength(1);
    expect(issues[0]?.policyId).toBe("bad-resource-in");
  });

  it("flags an undeclared entity type in an is scope", () => {
    const policy = Policy.permit({
      id: "bad-is",
      resource: Policy.isType("Robot"),
    });
    const issues = AuthorizationModel.validatePolicies(baseModel, [policy]);
    expect(issues).toHaveLength(1);
    expect(issues[0]?.policyId).toBe("bad-is");
    expect(issues[0]?.message).toContain("Robot");
  });

  it("flags an action scope referencing a non-Action entity type", () => {
    const policy = Policy.permit({
      id: "bad-action-type",
      action: Policy.eq(Entity.ref("Document", "doc-1")),
    });
    const issues = AuthorizationModel.validatePolicies(baseModel, [policy]);
    expect(issues).toHaveLength(1);
    expect(issues[0]?.policyId).toBe("bad-action-type");
    expect(issues[0]?.message).toContain("must reference Action entities");
  });

  it("flags an action scope naming an undeclared action id", () => {
    const policy = Policy.permit({
      id: "bad-action-id",
      action: Policy.eq(Entity.ref("Action", "doc:archive")),
    });
    const issues = AuthorizationModel.validatePolicies(baseModel, [policy]);
    expect(issues).toHaveLength(1);
    expect(issues[0]?.policyId).toBe("bad-action-id");
    expect(issues[0]?.message).toContain("doc:archive");
  });

  it("allows an action scope naming a memberOf group id (legal in-target)", () => {
    const policy = Policy.permit({
      id: "group-action",
      action: Policy.inScope(Entity.ref("Action", "doc:all")),
    });
    expect(AuthorizationModel.validatePolicies(baseModel, [policy])).toEqual([]);
  });

  it("flags an eq-action policy whose principal is-scope violates appliesTo", () => {
    const policy = Policy.permit({
      id: "bad-appliesto-principal",
      action: Policy.eq(Entity.ref("Action", "doc:read")),
      principal: Policy.isType("Folder"),
    });
    const issues = AuthorizationModel.validatePolicies(baseModel, [policy]);
    expect(issues).toHaveLength(1);
    expect(issues[0]?.policyId).toBe("bad-appliesto-principal");
    expect(issues[0]?.message).toContain("does not apply to principal type");
  });

  it("flags an eq-action policy whose resource eq-scope pins a type outside appliesTo", () => {
    const policy = Policy.permit({
      id: "bad-appliesto-resource",
      action: Policy.eq(Entity.ref("Action", "doc:read")),
      resource: Policy.eq(Entity.ref("Folder", "f1")),
    });
    const issues = AuthorizationModel.validatePolicies(baseModel, [policy]);
    expect(issues).toHaveLength(1);
    expect(issues[0]?.policyId).toBe("bad-appliesto-resource");
    expect(issues[0]?.message).toContain("does not apply to resource type");
  });

  it("does not check appliesTo for any/in principal or resource scopes", () => {
    const anyPolicy = Policy.permit({
      id: "any-scope",
      action: Policy.eq(Entity.ref("Action", "doc:read")),
      principal: Policy.any,
      resource: Policy.any,
    });
    const inPolicy = Policy.permit({
      id: "in-scope",
      action: Policy.eq(Entity.ref("Action", "doc:read")),
      resource: Policy.inScope(Entity.ref("Folder", "f1")),
    });
    expect(AuthorizationModel.validatePolicies(baseModel, [anyPolicy])).toEqual([]);
    expect(AuthorizationModel.validatePolicies(baseModel, [inPolicy])).toEqual([]);
  });

  it("flags entity literals inside when conditions with undeclared types", () => {
    const policy = Policy.permit({
      id: "bad-condition",
      when: Condition.eq(
        Condition.attr("resource", "owner"),
        Condition.entityLit(Entity.ref("Robot", "r1")),
      ),
    });
    const issues = AuthorizationModel.validatePolicies(baseModel, [policy]);
    expect(issues).toHaveLength(1);
    expect(issues[0]?.policyId).toBe("bad-condition");
    expect(issues[0]?.message).toContain("condition references undeclared entity type");
  });

  it("does not flag condition entity literals with declared types", () => {
    const policy = Policy.permit({
      id: "ok-condition",
      when: Condition.eq(Condition.attr("resource", "owner"), Condition.entityLit(alice)),
    });
    expect(AuthorizationModel.validatePolicies(baseModel, [policy])).toEqual([]);
  });

  it("carries the offending policyId for every issue, even across multiple violations", () => {
    const good = Policy.permit({ id: "ok", principal: Policy.isType("User") });
    const bad1 = Policy.permit({ id: "bad-1", principal: Policy.isType("Robot") });
    const bad2 = Policy.permit({ id: "bad-2", resource: Policy.isType("Alien") });
    const issues = AuthorizationModel.validatePolicies(baseModel, [good, bad1, bad2]);
    expect(
      Arr.sort(
        issues.map((i) => i.policyId),
        Order.String,
      ),
    ).toEqual(["bad-1", "bad-2"]);
  });
});
