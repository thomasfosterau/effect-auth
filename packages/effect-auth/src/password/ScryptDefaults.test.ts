import { describe, it, expect, vi, beforeEach, assert } from "vite-plus/test";
import * as crypto from "node:crypto";
import { Effect, Result } from "effect";
import { PasswordHasher, scryptHasher } from "./Password.ts";

// Pins scrypt's production defaults (N = 2^17, r = 8, p = 1) without running
// a 128 MiB key derivation: `crypto.scrypt` is replaced by a stub that records
// the parameters it was asked for and returns a zero key at once. Because the
// stub skips Node's parameter validation, it also checks `maxmem` covers what
// OpenSSL's scrypt allocates, 128 * r * (N + p + 2) bytes: Node's 32 MiB
// default is far below that at these parameters, and the real call fails with
// ERR_CRYPTO_INVALID_SCRYPT_PARAMS when `maxmem` is too small. The
// round-trip tests in `Password.test.ts` run the real KDF at a cheap explicit
// cost, so neither file depends on how fast the machine is (#270).
vi.mock("node:crypto", async (importOriginal) => {
  const actual = await importOriginal<typeof import("node:crypto")>();
  return {
    ...actual,
    scrypt: vi.fn(
      (
        _password: crypto.BinaryLike,
        _salt: crypto.BinaryLike,
        keylen: number,
        _options: crypto.ScryptOptions,
        callback: (error: Error | null, derivedKey: Buffer) => void,
      ) => callback(null, Buffer.alloc(keylen)),
    ),
  };
});

const scrypt = vi.mocked(crypto.scrypt);

beforeEach(() => {
  scrypt.mockClear();
});

const expectDefaultHash = (hash: string) => {
  const [algorithm, cost, blockSize, parallelization, salt, key] = hash.split("$");
  expect({ algorithm, cost, blockSize, parallelization }).toEqual({
    algorithm: "scrypt",
    cost: "131072",
    blockSize: "8",
    parallelization: "1",
  });
  expect(salt).toMatch(/^[0-9a-f]{32}$/);
  expect(key).toMatch(/^[0-9a-f]{128}$/);
  expect(scrypt).toHaveBeenCalledOnce();
  const options = scrypt.mock.calls[0]![3];
  expect(options).toMatchObject({ N: 131072, r: 8, p: 1 });
  expect(options.maxmem).toBeGreaterThanOrEqual(128 * 8 * (131072 + 1 + 2));
};

describe("scrypt defaults", () => {
  it("scryptHasher() derives and encodes N = 2^17, r = 8, p = 1", async () => {
    const { hash } = await Effect.runPromise(scryptHasher().hash("default-params"));
    expectDefaultHash(hash);
  });

  it("PasswordHasher.layerScrypt() uses the same defaults", async () => {
    const program = Effect.gen(function* () {
      const hasher = yield* PasswordHasher;
      return yield* hasher.hash("default-params");
    });
    const { hash } = await Effect.runPromise(Effect.provide(program, PasswordHasher.layerScrypt()));
    expectDefaultHash(hash);
  });

  it("needsRehash flags any hash below the default cost", () => {
    const hasher = scryptHasher();
    const salt = "00".repeat(16);
    const key = "00".repeat(64);
    expect(hasher.needsRehash!(`scrypt$131072$8$1$${salt}$${key}`)).toBe(false);
    expect(hasher.needsRehash!(`scrypt$65536$8$1$${salt}$${key}`)).toBe(true);
  });

  it("verify accepts a stored hash at the default parameters", async () => {
    // The stub derives a zero key, so a stored all-zero key verifies.
    const stored = `scrypt$131072$8$1$${"00".repeat(16)}$${"00".repeat(64)}`;
    expect(await Effect.runPromise(scryptHasher().verify("pw", stored))).toBe(true);
    expect(scrypt.mock.calls[0]![3]).toMatchObject({ N: 131072, r: 8, p: 1 });
  });

  it("verify accepts a hash at a configured cost above the 256 MiB floor", async () => {
    // N = 2^21 with r = 8 needs 2 GiB. The cap follows the configured cost, so
    // the hasher's own hashes still verify; the 256 MiB floor alone would refuse them.
    const hasher = scryptHasher({ cost: 2 ** 21 });
    const hashed = await Effect.runPromise(hasher.hash("pw"));
    expect(await Effect.runPromise(hasher.verify("pw", hashed.hash))).toBe(true);
  });

  it.each([
    ["p = 1000000", "1024", "8", "1000000"],
    ["N * r above the memory cap", String(2 ** 20), "32", "1"],
  ])("refuses a stored hash with %s before running the KDF", async (_label, N, r, p) => {
    const stored = `scrypt$${N}$${r}$${p}$${"00".repeat(16)}$${"00".repeat(64)}`;
    const result = await Effect.runPromise(Effect.result(scryptHasher().verify("pw", stored)));
    expect(result._tag).toBe("Failure");
    assert(Result.isFailure(result));
    expect(result.failure._tag).toBe("HashingError");
    // Refused before any derivation: an unguarded verify would ask Node for
    // about 1 GB (p = 1000000) or 4 GiB (N = 2^20, r = 32).
    expect(scrypt).not.toHaveBeenCalled();
  });

  it.each([
    ["cost", { cost: Number.NaN }],
    ["blockSize", { blockSize: Number.POSITIVE_INFINITY }],
    ["parallelization", { parallelization: Number.NaN }],
  ])("a non-finite configured %s does not lift verify's caps", async (_label, options) => {
    // Caps are max(floor, configured value); a NaN or Infinity option must
    // not turn them into NaN/Infinity (every `>` comparison false).
    const hasher = scryptHasher(options);
    for (const stored of [
      `scrypt$${2 ** 20}$32$1$${"00".repeat(16)}$${"00".repeat(64)}`,
      `scrypt$1024$8$1000000$${"00".repeat(16)}$${"00".repeat(64)}`,
    ]) {
      const result = await Effect.runPromise(Effect.result(hasher.verify("pw", stored)));
      expect(result._tag).toBe("Failure");
    }
    expect(scrypt).not.toHaveBeenCalled();
  });
});
