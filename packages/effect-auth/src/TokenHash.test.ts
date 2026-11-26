import { describe, expect, it } from "vite-plus/test";
import * as Effect from "effect/Effect";
import { Digest } from "effect/crypto";
import { sha256Hex } from "./testing/Sha256.ts";
import { constantTimeHashEqual, hashToken, timingSafeEqualBytes } from "./TokenHash.ts";

describe("hashToken", () => {
  it("is the SHA-256 hex digest of the token's UTF-8 bytes", async () => {
    const digest = (token: string) =>
      Effect.runPromise(hashToken(token).pipe(Effect.provide(Digest.layerWebCrypto)));
    expect(await digest("abc")).toBe(
      "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
    );
    expect(await digest("é-token")).toBe(sha256Hex("é-token"));
  });
});

describe("timingSafeEqualBytes", () => {
  it("is false for sequences of different lengths", () => {
    expect(timingSafeEqualBytes(new Uint8Array([1, 2]), new Uint8Array([1, 2]))).toBe(true);
    expect(timingSafeEqualBytes(new Uint8Array([1, 2]), new Uint8Array([1, 2, 0]))).toBe(false);
  });
});

describe("constantTimeHashEqual", () => {
  it("is true for the same digest and false for another", () => {
    expect(constantTimeHashEqual(sha256Hex("a"), sha256Hex("a"))).toBe(true);
    expect(constantTimeHashEqual(sha256Hex("a"), sha256Hex("b"))).toBe(false);
  });

  it("equates nothing that is not hex, not even two equal strings", () => {
    expect(constantTimeHashEqual("not-hex", "not-hex")).toBe(false);
    expect(constantTimeHashEqual("zz", "yy")).toBe(false);
    expect(constantTimeHashEqual(sha256Hex("a"), `${sha256Hex("a")}z`)).toBe(false);
  });
});
