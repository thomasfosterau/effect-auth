import { describe, it, expect } from "vite-plus/test";
import {
  makePermission,
  parsePermission,
  formatPermission,
  permissionMatches,
} from "./Permission.js";

describe("Permission", () => {
  describe("parsePermission / formatPermission", () => {
    it("parses resource:action", () => {
      expect(parsePermission("posts:read")).toEqual({ resource: "posts", action: "read" });
    });

    it("parses wildcard action", () => {
      expect(parsePermission("posts:*")).toEqual({ resource: "posts", action: "*" });
    });

    it("defaults missing action to wildcard", () => {
      expect(parsePermission("posts")).toEqual({ resource: "posts", action: "*" });
    });

    it("trims whitespace", () => {
      expect(parsePermission("  posts : read ")).toEqual({ resource: "posts", action: "read" });
    });

    it("round-trips through format", () => {
      const permission = makePermission("users", "delete");
      expect(parsePermission(formatPermission(permission))).toEqual(permission);
    });
  });

  describe("permissionMatches", () => {
    it("matches exact resource and action", () => {
      expect(
        permissionMatches(
          { resource: "posts", action: "read" },
          { resource: "posts", action: "read" },
        ),
      ).toBe(true);
    });

    it("denies a different action", () => {
      expect(
        permissionMatches(
          { resource: "posts", action: "read" },
          { resource: "posts", action: "delete" },
        ),
      ).toBe(false);
    });

    it("matches a wildcard action", () => {
      expect(
        permissionMatches(
          { resource: "posts", action: "*" },
          { resource: "posts", action: "delete" },
        ),
      ).toBe(true);
    });

    it("matches a wildcard resource", () => {
      expect(
        permissionMatches({ resource: "*", action: "read" }, { resource: "users", action: "read" }),
      ).toBe(true);
    });

    it("matches a full wildcard (superadmin)", () => {
      expect(
        permissionMatches(
          { resource: "*", action: "*" },
          { resource: "anything", action: "whatever" },
        ),
      ).toBe(true);
    });

    it("does not expand wildcards in the requested permission", () => {
      expect(
        permissionMatches({ resource: "posts", action: "read" }, { resource: "*", action: "*" }),
      ).toBe(false);
    });
  });
});
