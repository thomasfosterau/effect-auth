import { describe, it, expect } from "vite-plus/test";
import { Effect, Context } from "effect";
import {
  makeRoleBasedPolicy,
  requirePermission,
  requireAllPermissions,
  requireAnyPermission,
  can,
  allowAll,
  denyAll,
  anyOf,
  allOf,
  not,
  fromPredicate,
  RoleStore,
  AuthorizationPolicy,
} from "./Authorization.js";
import { PermissionDeniedError } from "./Errors.js";

// Mock role store for testing
const mockRoleStore: RoleStore = {
  getUserRoles: (userId) =>
    Effect.sync(() => {
      const roles: Record<string, string[]> = {
        "admin-user": ["admin"],
        "editor-user": ["editor"],
        "viewer-user": ["viewer"],
        "multi-user": ["editor", "viewer"],
      };
      return roles[userId] || [];
    }),

  getRolePermissions: (role) =>
    Effect.sync(() => {
      const permissions: Record<string, Array<{ resource: string; action: string }>> = {
        admin: [
          { resource: "posts", action: "create" },
          { resource: "posts", action: "read" },
          { resource: "posts", action: "update" },
          { resource: "posts", action: "delete" },
          { resource: "users", action: "read" },
          { resource: "users", action: "delete" },
        ],
        editor: [
          { resource: "posts", action: "create" },
          { resource: "posts", action: "read" },
          { resource: "posts", action: "update" },
        ],
        viewer: [{ resource: "posts", action: "read" }],
      };
      return permissions[role] || [];
    }),
};

const RoleStoreTest = Context.make(RoleStore, mockRoleStore);

describe("Authorization", () => {
  describe("makeRoleBasedPolicy", () => {
    it("should allow admin to delete users", async () => {
      const program = Effect.gen(function* () {
        const policy = yield* makeRoleBasedPolicy();
        return yield* policy.checkPermission("admin-user", "users", "delete");
      });

      const result = await Effect.runPromise(Effect.provide(program, RoleStoreTest));

      expect(result).toBe(true);
    });

    it("should allow editor to create posts", async () => {
      const program = Effect.gen(function* () {
        const policy = yield* makeRoleBasedPolicy();
        return yield* policy.checkPermission("editor-user", "posts", "create");
      });

      const result = await Effect.runPromise(Effect.provide(program, RoleStoreTest));

      expect(result).toBe(true);
    });

    it("should deny editor from deleting users", async () => {
      const program = Effect.gen(function* () {
        const policy = yield* makeRoleBasedPolicy();
        return yield* policy.checkPermission("editor-user", "users", "delete");
      });

      const result = await Effect.runPromise(Effect.provide(program, RoleStoreTest));

      expect(result).toBe(false);
    });

    it("should allow viewer to read posts", async () => {
      const program = Effect.gen(function* () {
        const policy = yield* makeRoleBasedPolicy();
        return yield* policy.checkPermission("viewer-user", "posts", "read");
      });

      const result = await Effect.runPromise(Effect.provide(program, RoleStoreTest));

      expect(result).toBe(true);
    });

    it("should deny viewer from creating posts", async () => {
      const program = Effect.gen(function* () {
        const policy = yield* makeRoleBasedPolicy();
        return yield* policy.checkPermission("viewer-user", "posts", "create");
      });

      const result = await Effect.runPromise(Effect.provide(program, RoleStoreTest));

      expect(result).toBe(false);
    });

    it("should handle multiple roles correctly", async () => {
      const program = Effect.gen(function* () {
        const policy = yield* makeRoleBasedPolicy();
        // User has both editor and viewer roles
        const canCreate = yield* policy.checkPermission("multi-user", "posts", "create");
        const canRead = yield* policy.checkPermission("multi-user", "posts", "read");
        const canDelete = yield* policy.checkPermission("multi-user", "posts", "delete");
        return { canCreate, canRead, canDelete };
      });

      const result = await Effect.runPromise(Effect.provide(program, RoleStoreTest));

      expect(result.canCreate).toBe(true); // From editor role
      expect(result.canRead).toBe(true); // From both roles
      expect(result.canDelete).toBe(false); // Not in any role
    });

    it("should deny unknown users", async () => {
      const program = Effect.gen(function* () {
        const policy = yield* makeRoleBasedPolicy();
        return yield* policy.checkPermission("unknown-user", "posts", "read");
      });

      const result = await Effect.runPromise(Effect.provide(program, RoleStoreTest));

      expect(result).toBe(false);
    });
  });

  describe("requirePermission", () => {
    // Create a mock authorization policy for testing requirePermission
    const mockPolicy: AuthorizationPolicy = {
      checkPermission: (userId, resource, action) =>
        Effect.sync(() => {
          // Simple mock: only admin-user can do everything
          return userId === "admin-user";
        }),
    };

    const PolicyTest = Context.make(AuthorizationPolicy, mockPolicy);

    it("should succeed when permission is granted", async () => {
      const program = requirePermission("admin-user", "posts", "create");

      await Effect.runPromise(Effect.provide(program, PolicyTest));
      // If we get here without error, the test passes
    });

    it("should fail with PermissionDeniedError when permission is denied", async () => {
      const program = requirePermission("viewer-user", "posts", "create");

      const result = await Effect.runPromise(Effect.result(Effect.provide(program, PolicyTest)));

      expect(result._tag).toBe("Failure");
      if (result._tag === "Failure") {
        expect(result.failure._tag).toBe("PermissionDeniedError");
        expect(result.failure.resource).toBe("posts");
        expect(result.failure.action).toBe("create");
      }
    });

    it("should include descriptive error message", async () => {
      const program = requirePermission("viewer-user", "users", "delete");

      const result = await Effect.runPromise(Effect.result(Effect.provide(program, PolicyTest)));

      expect(result._tag).toBe("Failure");
      if (result._tag === "Failure") {
        expect(result.failure.message).toContain("Permission denied");
        expect(result.failure.message).toContain("delete");
        expect(result.failure.message).toContain("users");
      }
    });
  });

  describe("combinators", () => {
    const run = (policy: AuthorizationPolicy) =>
      Effect.runPromise(policy.checkPermission("user", "posts", "read"));

    it("allowAll grants everything", async () => {
      expect(await run(allowAll)).toBe(true);
    });

    it("denyAll denies everything", async () => {
      expect(await run(denyAll)).toBe(false);
    });

    it("not negates a policy", async () => {
      expect(await run(not(denyAll))).toBe(true);
      expect(await run(not(allowAll))).toBe(false);
    });

    it("anyOf grants if any policy grants", async () => {
      expect(await run(anyOf(denyAll, allowAll))).toBe(true);
      expect(await run(anyOf(denyAll, denyAll))).toBe(false);
      expect(await run(anyOf())).toBe(false);
    });

    it("allOf grants only if every policy grants", async () => {
      expect(await run(allOf(allowAll, allowAll))).toBe(true);
      expect(await run(allOf(allowAll, denyAll))).toBe(false);
      expect(await run(allOf())).toBe(true);
    });

    it("fromPredicate builds a policy from a rule", async () => {
      const ownPosts = fromPredicate((userId, resource) =>
        Effect.succeed(userId === "owner" && resource === "posts"),
      );
      expect(await Effect.runPromise(ownPosts.checkPermission("owner", "posts", "read"))).toBe(
        true,
      );
      expect(await Effect.runPromise(ownPosts.checkPermission("other", "posts", "read"))).toBe(
        false,
      );
    });
  });

  describe("guards", () => {
    const mockPolicy: AuthorizationPolicy = {
      checkPermission: (_userId, resource, action) =>
        Effect.succeed(resource === "posts" && (action === "read" || action === "update")),
    };
    const PolicyTest = Context.make(AuthorizationPolicy, mockPolicy);

    it("can returns a boolean", async () => {
      const yes = await Effect.runPromise(Effect.provide(can("u", "posts", "read"), PolicyTest));
      const no = await Effect.runPromise(Effect.provide(can("u", "posts", "delete"), PolicyTest));
      expect(yes).toBe(true);
      expect(no).toBe(false);
    });

    it("requireAllPermissions succeeds when all granted", async () => {
      const program = requireAllPermissions("u", [
        { resource: "posts", action: "read" },
        { resource: "posts", action: "update" },
      ]);
      await Effect.runPromise(Effect.provide(program, PolicyTest));
    });

    it("requireAllPermissions fails on the first missing", async () => {
      const program = requireAllPermissions("u", [
        { resource: "posts", action: "read" },
        { resource: "posts", action: "delete" },
      ]);
      const result = await Effect.runPromise(Effect.result(Effect.provide(program, PolicyTest)));
      expect(result._tag).toBe("Failure");
      if (result._tag === "Failure") {
        expect(result.failure._tag).toBe("PermissionDeniedError");
        expect(result.failure.action).toBe("delete");
      }
    });

    it("requireAnyPermission succeeds when at least one granted", async () => {
      const program = requireAnyPermission("u", [
        { resource: "posts", action: "delete" },
        { resource: "posts", action: "read" },
      ]);
      await Effect.runPromise(Effect.provide(program, PolicyTest));
    });

    it("requireAnyPermission fails when none granted", async () => {
      const program = requireAnyPermission("u", [
        { resource: "users", action: "delete" },
        { resource: "posts", action: "delete" },
      ]);
      const result = await Effect.runPromise(Effect.result(Effect.provide(program, PolicyTest)));
      expect(result._tag).toBe("Failure");
      if (result._tag === "Failure") {
        expect(result.failure._tag).toBe("PermissionDeniedError");
        expect(result.failure.message).toContain("any of");
      }
    });
  });
});
