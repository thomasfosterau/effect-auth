import { describe, it, expect, vi, beforeEach } from "vite-plus/test";
import * as crypto from "node:crypto";
import { Effect } from "effect";
import { PasswordHasher, scryptHasher } from "./Password.ts";

// Pins scrypt's production defaults (N = 2^17, r = 8, p = 1) without running
// a 128 MiB key derivation: `crypto.scrypt` is replaced by a stub that records
// the parameters it was asked for and returns a zero key at once. The
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
  expect(scrypt.mock.calls[0]![3]).toMatchObject({ N: 131072, r: 8, p: 1 });
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
});
