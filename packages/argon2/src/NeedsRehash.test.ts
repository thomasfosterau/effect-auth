/**
 * `needsRehash`: a stored hash weaker than the configured costs, or one
 * `verify` refuses, is replaced on the next successful sign-in; one at least
 * as strong in every parameter is kept.
 */
import { assert, describe, expect, it } from "vite-plus/test";
import * as Effect from "effect/Effect";
import { hashWasmFixtures } from "./HashWasm.fixtures.ts";
import * as Argon2 from "./index.ts";

/** 16-byte salt and 32-byte digest, both a fixture's. */
const SALT = "MDEyMzQ1Njc4OWFiY2RlZg";
const DIGEST = "gy5SuVm5Z7Vw7keB9se9p87QGcomaseB/S2U1OhTsM0";

const stored = (
  m: number,
  t: number,
  p: number,
  { variant = "argon2id", salt = SALT, digest = DIGEST } = {},
): string => `$${variant}$v=19$m=${m},t=${t},p=${p}$${salt}$${digest}`;

const hasher = Argon2.Argon2.argon2Hasher({ memoryCost: 19456, timeCost: 2, parallelism: 2 });
const needsRehash = (hash: string): boolean => {
  assert(hasher.needsRehash !== undefined, "the hasher reports rehashing");
  return hasher.needsRehash(hash);
};

describe("needsRehash", () => {
  it("keeps a hash the hasher has just written", async () => {
    const { hash } = await Effect.runPromise(hasher.hash("correct horse battery staple"));
    expect(needsRehash(hash)).toBe(false);
  });

  it("keeps a hash at or above the configured costs in every parameter", () => {
    expect(needsRehash(stored(19456, 2, 2))).toBe(false);
    expect(needsRehash(stored(65536, 3, 4))).toBe(false);
    expect(needsRehash(stored(19456, 2, 2, { salt: `${SALT}${SALT}` }))).toBe(false);
  });

  it.each([
    ["a lower m", stored(8192, 2, 2)],
    ["a lower t", stored(19456, 1, 2)],
    ["a lower p", stored(19456, 2, 1)],
    ["a lower t, though a higher m", stored(65536, 1, 2)],
    ["a shorter salt", stored(19456, 2, 2, { salt: "MDEyMzQ1Njc" })],
    ["a shorter digest", stored(19456, 2, 2, { digest: "gy5SuVm5Z7Vw7keB9se9p87Q" })],
    ["argon2i", stored(19456, 2, 2, { variant: "argon2i" })],
    ["argon2d", stored(19456, 2, 2, { variant: "argon2d" })],
  ])("replaces a hash with %s", (_, hash) => {
    expect(needsRehash(hash)).toBe(true);
  });

  it("replaces the default profile's hashes once the costs are raised", () => {
    const fixture = hashWasmFixtures[0];
    assert(fixture !== undefined, "a hash-wasm fixture exists");
    expect(Argon2.Argon2.argon2Hasher().needsRehash?.(fixture.hash)).toBe(false);
    expect(
      Argon2.Argon2.argon2Hasher(Argon2.Common.serverProfile).needsRehash?.(fixture.hash),
    ).toBe(true);
  });

  it.each([
    ["an empty string", ""],
    ["a malformed string", "$argon2id$v=19$m=19456"],
    ["another algorithm", "$pbkdf2-sha256$i=600000$c2FsdA$ZGlnZXN0"],
    ["Argon2 v=16", stored(19456, 2, 2).replace("v=19", "v=16")],
    ["a repeated parameter", `$argon2id$v=19$m=19456,t=2,p=2,m=19456$${SALT}$${DIGEST}`],
    ["costs over the verify ceiling", stored(262144, 2, 2)],
    ["a stored string over 512 characters", stored(19456, 2, 2, { digest: "A".repeat(600) })],
  ])("replaces a hash verify refuses: %s", (_, hash) => {
    expect(needsRehash(hash)).toBe(true);
  });
});
