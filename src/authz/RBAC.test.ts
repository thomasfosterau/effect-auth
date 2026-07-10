import { describe, it, expect } from "vite-plus/test";
import { Effect, Context } from "effect";
import * as RBAC from "./RBAC.ts";
import { RoleStore } from "./Authorization.ts";
import * as Authorization from "./Authorization.ts";
import { formatPermission } from "./Permission.ts";

describe("RBAC", () => {
  describe("RBAC.make", () => {
    it("builds from a plain record", async () => {
      const store = RBAC.make({
        userRoles: { "user-1": ["editor"] },
        rolePermissions: { editor: [{ resource: "posts", action: "update" }] },
      });

      const roles = await Effect.runPromise(store.getUserRoles("user-1"));
      const permissions = await Effect.runPromise(store.getRolePermissions("editor"));

      expect(roles).toEqual(["editor"]);
      expect(permissions).toEqual([{ resource: "posts", action: "update" }]);
    });

    it("builds from Maps", async () => {
      const store = RBAC.make({
        userRoles: new Map([["user-1", ["viewer"]]]),
        rolePermissions: new Map([["viewer", [{ resource: "posts", action: "read" }]]]),
      });

      const roles = await Effect.runPromise(store.getUserRoles("user-1"));
      expect(roles).toEqual(["viewer"]);
    });

    it("returns empty for unknown users and roles", async () => {
      const store = RBAC.make({ userRoles: {}, rolePermissions: {} });

      expect(await Effect.runPromise(store.getUserRoles("nobody"))).toEqual([]);
      expect(await Effect.runPromise(store.getRolePermissions("ghost"))).toEqual([]);
    });

    it("inherits permissions from parent roles transitively", async () => {
      const store = RBAC.make({
        userRoles: {},
        rolePermissions: {
          viewer: [{ resource: "posts", action: "read" }],
          editor: [{ resource: "posts", action: "update" }],
          admin: [{ resource: "users", action: "delete" }],
        },
        roleHierarchy: {
          editor: ["viewer"],
          admin: ["editor"],
        },
      });

      const permissions = await Effect.runPromise(store.getRolePermissions("admin"));
      const keys = permissions.map(formatPermission).sort();

      expect(keys).toEqual(["posts:read", "posts:update", "users:delete"]);
    });

    it("de-duplicates inherited permissions", async () => {
      const store = RBAC.make({
        userRoles: {},
        rolePermissions: {
          base: [{ resource: "posts", action: "read" }],
          editor: [{ resource: "posts", action: "read" }],
        },
        roleHierarchy: { editor: ["base"] },
      });

      const permissions = await Effect.runPromise(store.getRolePermissions("editor"));
      expect(permissions).toEqual([{ resource: "posts", action: "read" }]);
    });

    it("tolerates cycles in the hierarchy", async () => {
      const store = RBAC.make({
        userRoles: {},
        rolePermissions: {
          a: [{ resource: "x", action: "read" }],
          b: [{ resource: "y", action: "read" }],
        },
        roleHierarchy: { a: ["b"], b: ["a"] },
      });

      const permissions = await Effect.runPromise(store.getRolePermissions("a"));
      const keys = permissions.map(formatPermission).sort();
      expect(keys).toEqual(["x:read", "y:read"]);
    });
  });

  describe("integration with Authorization.make", () => {
    it("grants inherited and wildcard permissions", async () => {
      const store = RBAC.make({
        userRoles: {
          "admin-user": ["admin"],
          "editor-user": ["editor"],
        },
        rolePermissions: {
          viewer: [{ resource: "posts", action: "read" }],
          editor: [{ resource: "posts", action: "update" }],
          admin: [{ resource: "*", action: "*" }],
        },
        roleHierarchy: { editor: ["viewer"] },
      });

      const program = Effect.gen(function* () {
        const policy = yield* Authorization.make();
        return {
          editorCanRead: yield* policy.checkPermission("editor-user", "posts", "read"),
          editorCanUpdate: yield* policy.checkPermission("editor-user", "posts", "update"),
          editorCanDelete: yield* policy.checkPermission("editor-user", "posts", "delete"),
          adminCanAnything: yield* policy.checkPermission("admin-user", "anything", "destroy"),
        };
      });

      const result = await Effect.runPromise(
        Effect.provide(program, Context.make(RoleStore, store)),
      );

      expect(result.editorCanRead).toBe(true); // inherited from viewer
      expect(result.editorCanUpdate).toBe(true);
      expect(result.editorCanDelete).toBe(false);
      expect(result.adminCanAnything).toBe(true); // *:* wildcard
    });
  });
});
