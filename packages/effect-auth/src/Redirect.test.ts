import { describe, expect, it } from "vite-plus/test";
import { safeRedirect } from "./Redirect.ts";

describe("safeRedirect", () => {
  it.each(["/", "/dashboard", "/dashboard?tab=1#top", "/a/b/../c", "/%2F%2Fevil.example"])(
    "follows the same-origin path %s",
    (target) => {
      expect(safeRedirect(target, "/fallback")).toBe(target);
    },
  );

  it.each([
    "https://evil.example",
    "http://evil.example/",
    "//evil.example",
    "///evil.example",
    "/\\evil.example",
    "\\\\evil.example",
    "javascript:alert(1)",
    "evil.example",
    "dashboard",
    "/\t/evil.example",
    "/\n/evil.example",
    "/\u0000",
    " /dashboard",
    "",
  ])("falls back for %j", (target) => {
    expect(safeRedirect(target, "/fallback")).toBe("/fallback");
  });

  it("falls back for a missing target", () => {
    expect(safeRedirect(null, "/home")).toBe("/home");
    expect(safeRedirect(undefined, "/home")).toBe("/home");
  });
});
