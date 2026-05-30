import { describe, it, expect } from "vite-plus/test";
import { Effect, Context } from "effect";
import {
  makeRoleBasedPolicy,
  requirePermission,
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
});
