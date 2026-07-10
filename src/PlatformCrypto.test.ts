import { describe, it, expect } from "vite-plus/test";
import { Crypto, Effect } from "effect";
import { layer } from "./PlatformCrypto.ts";

describe("PlatformCrypto", () => {
  it("generates non-deterministic random bytes of the requested length", async () => {
    const program = Effect.gen(function* () {
      const crypto = yield* Crypto.Crypto;
      const a = yield* crypto.randomBytes(32);
      const b = yield* crypto.randomBytes(32);
      return { a, b };
    });

    const { a, b } = await Effect.runPromise(Effect.provide(program, layer));
    expect(a.length).toBe(32);
    expect(b.length).toBe(32);
    expect(Buffer.from(a).toString("hex")).not.toBe(Buffer.from(b).toString("hex"));
  });

  it("computes a correct SHA-256 digest", async () => {
    const program = Effect.gen(function* () {
      const crypto = yield* Crypto.Crypto;
      return yield* crypto.digest("SHA-256", new TextEncoder().encode("abc"));
    });

    const hash = await Effect.runPromise(Effect.provide(program, layer));
    // Known SHA-256("abc") test vector.
    expect(Buffer.from(hash).toString("hex")).toBe(
      "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
    );
  });

  it("generates a valid random UUIDv4", async () => {
    const program = Effect.gen(function* () {
      const crypto = yield* Crypto.Crypto;
      return yield* crypto.randomUUIDv4;
    });

    const uuid = await Effect.runPromise(Effect.provide(program, layer));
    expect(uuid).toMatch(/^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/);
  });
});
