import { describe, it, expect } from "vite-plus/test";
import { Effect } from "effect";
import { Hex } from "effect/encoding";
import { Digest, SecureRandom } from "effect/crypto";
import { layer } from "./PlatformCrypto.ts";

describe("PlatformCrypto", () => {
  it("generates non-deterministic random bytes of the requested length", async () => {
    const { a, b } = await Effect.runPromise(
      Effect.provide(
        Effect.gen(function* () {
          const crypto = yield* SecureRandom.SecureRandom;
          const a = yield* crypto.randomBytes(32);
          const b = yield* crypto.randomBytes(32);
          return { a, b };
        }),
        layer,
      ),
    );
    expect(a.length).toBe(32);
    expect(b.length).toBe(32);
    expect(Hex.encode(a)).not.toBe(Hex.encode(b));
  });

  it("computes a correct SHA-256 digest", async () => {
    const hash = await Effect.runPromise(
      Effect.provide(
        Effect.gen(function* () {
          const digest = yield* Digest.Digest;
          return yield* digest.digest(Digest.sha256, new TextEncoder().encode("abc"));
        }),
        layer,
      ),
    );
    // Known SHA-256("abc") test vector.
    expect(Hex.encode(hash)).toBe(
      "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
    );
  });

  it("generates a valid random UUIDv4", async () => {
    const uuid = await Effect.runPromise(
      Effect.provide(
        Effect.gen(function* () {
          const crypto = yield* SecureRandom.SecureRandom;
          return yield* crypto.uuidV4();
        }),
        layer,
      ),
    );
    expect(uuid).toMatch(/^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/);
  });
});
