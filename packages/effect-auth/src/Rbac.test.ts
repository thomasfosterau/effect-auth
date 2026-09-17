import { describe, it, expect } from "vite-plus/test";
import { Effect } from "effect";
import * as Rbac from "./Rbac.ts";
import * as Authorizer from "./Authorizer.ts";
import * as AuthorizationModel from "./AuthorizationModel.ts";
import * as Entity from "./Entity.ts";
import * as Policy from "./Policy.ts";

const config: Rbac.RbacConfig = {
  userRoles: {
    "admin-user": ["admin"],
    "editor-user": ["editor"],
    "viewer-user": ["viewer"],
  },
  rolePermissions: {
    viewer: [{ resource: "posts", action: "read" }],
    editor: [{ resource: "posts", action: "update" }],
    admin: [{ resource: "*", action: "*" }],
  },
  roleHierarchy: { editor: ["viewer"] },
};

/** Decide a `(userId, resource, action)` triple through the kernel. */
const decide = (
  rbac: Rbac.RbacConfig,
  userId: string,
  resource: string,
  action: string,
): Effect.Effect<Policy.Decision> =>
  Policy.decide(
    Rbac.policies(rbac),
    Policy.request({
      principal: Entity.ref("User", userId),
      action: Entity.ref("Action", action),
      resource: Entity.ref(resource, `${resource}-1`),
    }),
    Entity.slice(Rbac.entities(rbac)),
  );

describe("RBAC as policy-kernel sugar", () => {
  describe("policies", () => {
    it("emits one declarative permit per (role, permission) pair", () => {
      const built = Rbac.policies(config);

      expect(built).toHaveLength(3);
      expect(built.every((policy) => policy._tag === "DeclarativePolicy")).toBe(true);
      expect(built.every((policy) => policy.effect === "permit")).toBe(true);
      expect(built.map((policy) => policy.id).sort()).toEqual([
        "rbac:admin:*:*",
        "rbac:editor:posts:update",
        "rbac:viewer:posts:read",
      ]);
    });

    it("scopes a permission to its role, action and resource type", () => {
      const viewer = Rbac.policies(config).find((p) => p.id === "rbac:viewer:posts:read")!;

      expect(viewer.principal).toEqual(Policy.inScope(Rbac.roleRef("viewer")));
      expect(viewer.action).toEqual(Policy.eq(Entity.ref("Action", "read")));
      expect(viewer.resource).toEqual(Policy.isType("posts"));
    });

    it('maps "*" wildcards to unscoped slots', () => {
      const admin = Rbac.policies(config).find((p) => p.id === "rbac:admin:*:*")!;

      expect(admin.action).toEqual(Policy.any);
      expect(admin.resource).toEqual(Policy.any);
    });

    it("does not expand inherited permissions into extra policies", () => {
      // editor inherits viewer, but that is an entity-graph edge, not a
      // duplicated grant: still one policy per authored permission.
      expect(Rbac.policies(config)).toHaveLength(3);
    });

    it("de-duplicates a permission granted twice to the same role", () => {
      const built = Rbac.policies({
        userRoles: {},
        rolePermissions: {
          editor: [
            { resource: "posts", action: "read" },
            { resource: "posts", action: "read" },
          ],
        },
      });

      expect(built).toHaveLength(1);
    });

    it("reads Maps as well as records", () => {
      const built = Rbac.policies({
        userRoles: new Map([["user-1", ["viewer"]]]),
        rolePermissions: new Map([["viewer", [{ resource: "posts", action: "read" }]]]),
      });

      expect(built.map((policy) => policy.id)).toEqual(["rbac:viewer:posts:read"]);
    });
  });

  describe("entities", () => {
    it("gives each principal its roles as parents", () => {
      const slice = Entity.slice(Rbac.entities(config));

      expect(
        Entity.entityIn(slice, Entity.ref("User", "editor-user"), Rbac.roleRef("editor")),
      ).toBe(true);
      expect(
        Entity.entityIn(slice, Entity.ref("User", "viewer-user"), Rbac.roleRef("editor")),
      ).toBe(false);
    });

    it("carries role inheritance as Role -> Role hierarchy", () => {
      const slice = Entity.slice(Rbac.entities(config));

      expect(
        Entity.entityIn(slice, Entity.ref("User", "editor-user"), Rbac.roleRef("viewer")),
      ).toBe(true);
    });

    it("resolves inheritance transitively", () => {
      const slice = Entity.slice(
        Rbac.entities({
          userRoles: { "user-1": ["admin"] },
          rolePermissions: {},
          roleHierarchy: { admin: ["editor"], editor: ["viewer"] },
        }),
      );

      expect(Entity.entityIn(slice, Entity.ref("User", "user-1"), Rbac.roleRef("viewer"))).toBe(
        true,
      );
    });

    it("tolerates cycles in the hierarchy", () => {
      const slice = Entity.slice(
        Rbac.entities({
          userRoles: { "user-1": ["a"] },
          rolePermissions: { a: [{ resource: "x", action: "read" }] },
          roleHierarchy: { a: ["b"], b: ["a"] },
        }),
      );

      expect(Entity.entityIn(slice, Entity.ref("User", "user-1"), Rbac.roleRef("b"))).toBe(true);
      expect(Entity.entityIn(slice, Entity.ref("User", "user-1"), Rbac.roleRef("c"))).toBe(false);
    });

    it("honours principalType", () => {
      const slice = Entity.slice(
        Rbac.entities({
          userRoles: { "key-1": ["service"] },
          rolePermissions: {},
          principalType: "ApiKey",
        }),
      );

      expect(Entity.entityIn(slice, Entity.ref("ApiKey", "key-1"), Rbac.roleRef("service"))).toBe(
        true,
      );
      expect(Entity.entityIn(slice, Entity.ref("User", "key-1"), Rbac.roleRef("service"))).toBe(
        false,
      );
    });
  });

  describe("model", () => {
    it("declares the principal and role types as hierarchy members", () => {
      const declared = Rbac.model(config);

      expect(declared.entities["User"]).toEqual({ memberOf: ["Role"] });
      expect(declared.entities["Role"]).toEqual({ memberOf: ["Role"] });
    });

    it("declares every non-wildcard resource type and action", () => {
      const declared = Rbac.model(config);

      expect(Object.keys(declared.entities).sort()).toEqual(["Role", "User", "posts"]);
      expect(Object.keys(declared.actions).sort()).toEqual(["read", "update"]);
      expect(declared.actions["read"]).toEqual({
        appliesTo: { principal: ["User"], resource: ["posts"] },
      });
    });

    it("validates the policies it was derived from", () => {
      expect(
        AuthorizationModel.validatePolicies(Rbac.model(config), Rbac.policies(config)),
      ).toEqual([]);
    });
  });

  describe("decisions", () => {
    it("grants a directly granted permission", async () => {
      const decision = await Effect.runPromise(decide(config, "viewer-user", "posts", "read"));

      expect(decision.allowed).toBe(true);
      expect(decision.reason).toBe("permit");
      expect(decision.determining.map((outcome) => outcome.policyId)).toEqual([
        "rbac:viewer:posts:read",
      ]);
    });

    it("grants an inherited permission through the role hierarchy", async () => {
      const decision = await Effect.runPromise(decide(config, "editor-user", "posts", "read"));

      expect(decision.allowed).toBe(true);
      expect(decision.determining.map((outcome) => outcome.policyId)).toEqual([
        "rbac:viewer:posts:read",
      ]);
    });

    it("denies a permission no role grants", async () => {
      const decision = await Effect.runPromise(decide(config, "editor-user", "posts", "delete"));

      expect(decision.allowed).toBe(false);
      expect(decision.reason).toBe("default-deny");
    });

    it("does not grant a parent role its child's permissions", async () => {
      const decision = await Effect.runPromise(decide(config, "viewer-user", "posts", "update"));

      expect(decision.allowed).toBe(false);
    });

    it('honours the "*:*" superadmin wildcard', async () => {
      const decision = await Effect.runPromise(decide(config, "admin-user", "anything", "destroy"));

      expect(decision.allowed).toBe(true);
      expect(decision.determining.map((outcome) => outcome.policyId)).toEqual(["rbac:admin:*:*"]);
    });

    it('honours a resource-scoped "*" action wildcard', async () => {
      const scoped: Rbac.RbacConfig = {
        userRoles: { "user-1": ["postmaster"] },
        rolePermissions: { postmaster: [{ resource: "posts", action: "*" }] },
      };

      expect((await Effect.runPromise(decide(scoped, "user-1", "posts", "delete"))).allowed).toBe(
        true,
      );
      expect((await Effect.runPromise(decide(scoped, "user-1", "users", "delete"))).allowed).toBe(
        false,
      );
    });

    it("denies an unknown user", async () => {
      const decision = await Effect.runPromise(decide(config, "nobody", "posts", "read"));

      expect(decision.allowed).toBe(false);
      expect(decision.reason).toBe("default-deny");
    });

    it("carries the full trace, not just a boolean", async () => {
      const decision = await Effect.runPromise(decide(config, "viewer-user", "posts", "read"));

      expect(decision.outcomes).toHaveLength(3);
      expect(decision.outcomes.map((outcome) => outcome.result).sort()).toEqual([
        "matched",
        "not-matched",
        "not-matched",
      ]);
    });
  });

  describe("layer", () => {
    it("wires an Authorizer that decides for the CurrentPrincipal", async () => {
      const program = Effect.gen(function* () {
        const authorizer = yield* Authorizer.Authorizer;
        return {
          editorCanRead: yield* authorizer.check({
            action: "read",
            resource: Entity.ref("posts", "post-1"),
          }),
          editorCanUpdate: yield* authorizer.check({
            action: "update",
            resource: Entity.ref("posts", "post-1"),
          }),
          editorCanDelete: yield* authorizer.check({
            action: "delete",
            resource: Entity.ref("posts", "post-1"),
          }),
        };
      }).pipe(Authorizer.CurrentPrincipal.provide(Entity.ref("User", "editor-user")));

      const result = await Effect.runPromise(Effect.provide(program, Rbac.layer(config)));

      expect(result.editorCanRead).toBe(true); // inherited from viewer
      expect(result.editorCanUpdate).toBe(true);
      expect(result.editorCanDelete).toBe(false);
    });

    it("fails the enforced form with the decision trace attached", async () => {
      const program = Effect.gen(function* () {
        const authorizer = yield* Authorizer.Authorizer;
        return yield* authorizer.authorize({
          action: "delete",
          resource: Entity.ref("posts", "post-1"),
        });
      }).pipe(Authorizer.CurrentPrincipal.provide(Entity.ref("User", "viewer-user")));

      const exit = await Effect.runPromise(
        Effect.exit(Effect.provide(program, Rbac.layer(config))),
      );

      expect(exit._tag).toBe("Failure");
    });
  });
});
