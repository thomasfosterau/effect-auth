import { describe, expect, it } from "vite-plus/test";
import { constantTimeHashEqual, hashToken } from "./TokenHash.ts";

describe("constantTimeHashEqual", () => {
  it("is true for the same digest and false for another", () => {
    expect(constantTimeHashEqual(hashToken("a"), hashToken("a"))).toBe(true);
    expect(constantTimeHashEqual(hashToken("a"), hashToken("b"))).toBe(false);
  });

  it("equates nothing that is not hex, not even two equal strings", () => {
    expect(constantTimeHashEqual("not-hex", "not-hex")).toBe(false);
    expect(constantTimeHashEqual("zz", "yy")).toBe(false);
    expect(constantTimeHashEqual(hashToken("a"), `${hashToken("a")}z`)).toBe(false);
  });
});
