/**
 * Attacker-influenced names that are also members of `Object.prototype`
 * (#621). Role names, attribute paths and model ids are strings a caller or
 * an imported row can choose, so every lookup keyed by one reads only the
 * record's own keys: `constructor` and `__proto__` are unknown names, never
 * the prototype's members.
 */
import { describe, expect, it } from "vite-plus/test";
import * as Schema from "effect/Schema";
import * as AuthorizationModel from "./AuthorizationModel.ts";
import * as Condition from "./Condition.ts";
import * as Entity from "./Entity.ts";
import * as Policy from "./Policy.ts";
import * as Rbac from "./Rbac.ts";

const prototypeNames = ["constructor", "__proto__", "toString", "hasOwnProperty"] as const;

const doc = Entity.ref("Document", "d1");
const alice = Entity.ref("User", "alice");

const request: Condition.ConditionRequest = {
  principal: alice,
  action: Entity.ref("Action", "doc:read"),
  resource: doc,
  context: {},
};

const slice = Entity.slice([Entity.entity(doc, { attributes: { owner: "alice", tags: {} } })]);

describe("prototype-member names (#621)", () => {
  describe("Condition", () => {
    it.each(prototypeNames)("has(resource, %s) is false", (name) => {
      expect(Condition.evaluate(slice, request, Condition.has("resource", name))).toEqual({
        ok: true,
        value: false,
      });
      expect(Condition.evaluate(slice, request, Condition.has("resource", "tags", name))).toEqual({
        ok: true,
        value: false,
      });
      expect(Condition.evaluate(slice, request, Condition.has("context", name))).toEqual({
        ok: true,
        value: false,
      });
    });

    it.each(prototypeNames)("attr(resource, %s) is absent", (name) => {
      const result = Condition.evaluateOperand(slice, request, Condition.attr("resource", name));
      expect(result.ok).toBe(false);
      const nested = Condition.evaluateOperand(
        slice,
        request,
        Condition.attr("resource", "tags", name),
      );
      expect(nested.ok).toBe(false);
    });
  });

  describe("Entity", () => {
    it.each(prototypeNames)("getAttribute(%s) is null", (name) => {
      expect(Entity.getAttribute(slice, doc, name)).toBeNull();
    });

    it.each(prototypeNames)("attributeValueEquals reads only own keys (%s)", (name) => {
      // Same key count, and `name` is a key of the left record only: the
      // prototype member on the right must not stand in for it.
      expect(Entity.attributeValueEquals({ [name]: "x" }, { other: "x" })).toBe(false);
    });
  });

  describe("Rbac", () => {
    it.each(prototypeNames)("projects a role named %s with no parents", (role) => {
      const config: Rbac.RbacConfig = {
        userRoles: { "user-1": [role] },
        rolePermissions: {},
        roleHierarchy: { admin: ["editor"] },
      };
      const roleEntity = Rbac.entities(config).find((e) =>
        Entity.refEquals(e.ref, Rbac.roleRef(role)),
      );
      expect(roleEntity?.parents).toEqual([]);
    });
  });

  describe("AuthorizationModel", () => {
    const model = AuthorizationModel.make({
      entities: { User: {}, Document: { attributes: Schema.Struct({ owner: Schema.String }) } },
      actions: { "doc:read": { appliesTo: { principal: ["User"], resource: ["Document"] } } },
    });

    it.each(prototypeNames)("flags %s as an undeclared action, type and attribute", (name) => {
      const issues = AuthorizationModel.validatePolicies(model, [
        Policy.permit({ id: "action", action: Policy.eq(Entity.ref("Action", name)) }),
        Policy.permit({ id: "type", resource: Policy.isType(name) }),
        Policy.permit({
          id: "attribute",
          resource: Policy.isType("Document"),
          when: Condition.eq(Condition.attr("resource", name), Condition.lit("x")),
        }),
      ]);
      expect(issues.map((issue) => issue.policyId).toSorted()).toEqual([
        "action",
        "attribute",
        "type",
      ]);
    });
  });
});
