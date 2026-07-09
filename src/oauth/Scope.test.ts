import { describe, it, expect } from "vite-plus/test";
import { Effect } from "effect";
import {
  parseScopes,
  formatScopes,
  hasScope,
  hasAllScopes,
  hasAnyScope,
  requireScope,
  requireAllScopes,
} from "./Scope.js";

describe("Scope", () => {
  describe("parseScopes / formatScopes", () => {
    it("parses a space-delimited string", () => {
      expect(parseScopes("read:user write:repo")).toEqual(["read:user", "write:repo"]);
    });

    it("ignores extra whitespace", () => {
      expect(parseScopes("  read:user   write:repo  ")).toEqual(["read:user", "write:repo"]);
    });

    it("formats an iterable", () => {
      expect(formatScopes(["read:user", "write:repo"])).toBe("read:user write:repo");
    });
  });

  describe("hasScope", () => {
    it("works with a raw scope string", () => {
      expect(hasScope("read:user write:repo", "write:repo")).toBe(true);
      expect(hasScope("read:user", "write:repo")).toBe(false);
    });

    it("works with an iterable of scopes", () => {
      expect(hasScope(["read:user"], "read:user")).toBe(true);
    });
  });

  describe("hasAllScopes / hasAnyScope", () => {
    it("checks all scopes", () => {
      expect(hasAllScopes("a b c", ["a", "b"])).toBe(true);
      expect(hasAllScopes("a b", ["a", "c"])).toBe(false);
    });

    it("checks any scope", () => {
      expect(hasAnyScope("a b", ["x", "b"])).toBe(true);
      expect(hasAnyScope("a b", ["x", "y"])).toBe(false);
    });
  });

  describe("requireScope", () => {
    it("succeeds when granted", async () => {
      await Effect.runPromise(requireScope("read:user write:repo", "write:repo"));
    });

    it("fails with InsufficientScopeError when missing", async () => {
      const result = await Effect.runPromise(
        Effect.result(requireScope("read:user", "write:repo")),
      );

      expect(result._tag).toBe("Failure");
      if (result._tag === "Failure") {
        expect(result.failure._tag).toBe("InsufficientScopeError");
        expect(result.failure.requiredScope).toBe("write:repo");
        expect(result.failure.grantedScopes).toEqual(["read:user"]);
      }
    });
  });

  describe("requireAllScopes", () => {
    it("succeeds when all granted", async () => {
      await Effect.runPromise(requireAllScopes("a b c", ["a", "b"]));
    });

    it("reports missing scopes", async () => {
      const result = await Effect.runPromise(Effect.result(requireAllScopes("a", ["a", "b", "c"])));

      expect(result._tag).toBe("Failure");
      if (result._tag === "Failure") {
        expect(result.failure._tag).toBe("InsufficientScopeError");
        expect(result.failure.requiredScope).toBe("b c");
      }
    });
  });
});
