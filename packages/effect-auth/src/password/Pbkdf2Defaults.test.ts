import { describe, it, expect, vi, beforeEach } from "vite-plus/test";
import * as crypto from "node:crypto";
import { Effect } from "effect";
import { PasswordHasher, pbkdf2Hasher } from "./Password.ts";

// Pins PBKDF2's production default (600,000 iterations) and the `iterations`
// option without running a 600,000-iteration derivation: `crypto.pbkdf2` is
// replaced by a stub that records the arguments it was asked for and returns a
// zero key at once. The round trips at a cheap explicit count are in
// `Password.test.ts`, which runs the real KDF (#290).
vi.mock("node:crypto", async (importOriginal) => {
  const actual = await importOriginal<typeof import("node:crypto")>();
  return {
    ...actual,
    pbkdf2: vi.fn(
      (
        _password: crypto.BinaryLike,
        _salt: crypto.BinaryLike,
        _iterations: number,
        keylen: number,
        _digest: string,
        callback: (error: Error | null, derivedKey: Buffer) => void,
      ) => callback(null, Buffer.alloc(keylen)),
    ),
  };
});

const pbkdf2 = vi.mocked(crypto.pbkdf2);

beforeEach(() => {
  pbkdf2.mockClear();
});

const SALT = "00".repeat(16);
const KEY = "00".repeat(32);

describe("pbkdf2 defaults", () => {
  it("pbkdf2Hasher() derives and encodes 600,000 iterations", async () => {
    const { hash } = await Effect.runPromise(pbkdf2Hasher().hash("default-params"));
    expect(hash).toMatch(/^pbkdf2-sha256\$600000\$[0-9a-f]{32}\$[0-9a-f]{64}$/);
    expect(pbkdf2).toHaveBeenCalledOnce();
    expect(pbkdf2.mock.calls[0]![2]).toBe(600000);
  });

  it("an undefined iterations option is the default", async () => {
    const { hash } = await Effect.runPromise(
      pbkdf2Hasher({ iterations: undefined }).hash("default-params"),
    );
    expect(hash.startsWith("pbkdf2-sha256$600000$")).toBe(true);
  });

  it("PasswordHasher.layer() uses the same default", async () => {
    const program = Effect.gen(function* () {
      const hasher = yield* PasswordHasher;
      return yield* hasher.hash("default-params");
    });
    const { hash } = await Effect.runPromise(Effect.provide(program, PasswordHasher.layer()));
    expect(hash.startsWith("pbkdf2-sha256$600000$")).toBe(true);
    expect(pbkdf2.mock.calls[0]![2]).toBe(600000);
  });

  it("needsRehash flags any hash below the default count", () => {
    const hasher = pbkdf2Hasher();
    expect(hasher.needsRehash!(`pbkdf2-sha256$600000$${SALT}$${KEY}`)).toBe(false);
    expect(hasher.needsRehash!(`pbkdf2-sha256$599999$${SALT}$${KEY}`)).toBe(true);
  });
});

describe("pbkdf2 iterations option", () => {
  it("encodes the configured count and passes it to the KDF", async () => {
    const { hash } = await Effect.runPromise(pbkdf2Hasher({ iterations: 1000 }).hash("pw"));
    expect(hash.startsWith("pbkdf2-sha256$1000$")).toBe(true);
    expect(pbkdf2.mock.calls[0]![2]).toBe(1000);
  });

  it("PasswordHasher.layer({ iterations }) forwards the option", async () => {
    const program = Effect.gen(function* () {
      const hasher = yield* PasswordHasher;
      return yield* hasher.hash("pw");
    });
    const { hash } = await Effect.runPromise(
      Effect.provide(program, PasswordHasher.layer({ iterations: 1000 })),
    );
    expect(hash.startsWith("pbkdf2-sha256$1000$")).toBe(true);
    expect(pbkdf2.mock.calls[0]![2]).toBe(1000);
  });

  it("accepts 1 and Node's largest count, 2^31 - 1", async () => {
    for (const iterations of [1, 2 ** 31 - 1]) {
      pbkdf2.mockClear();
      const { hash } = await Effect.runPromise(pbkdf2Hasher({ iterations }).hash("pw"));
      expect(hash.startsWith(`pbkdf2-sha256$${iterations}$`)).toBe(true);
      expect(pbkdf2.mock.calls[0]![2]).toBe(iterations);
    }
  });

  it("needsRehash compares against the configured count, not the default", () => {
    const hasher = pbkdf2Hasher({ iterations: 1000 });
    expect(hasher.needsRehash!(`pbkdf2-sha256$1000$${SALT}$${KEY}`)).toBe(false);
    expect(hasher.needsRehash!(`pbkdf2-sha256$999$${SALT}$${KEY}`)).toBe(true);
    // A stronger stored hash is kept, even above the configured count.
    expect(hasher.needsRehash!(`pbkdf2-sha256$600000$${SALT}$${KEY}`)).toBe(false);
  });

  it("verify reads the count from the stored hash, not the configured one", async () => {
    const stored = `pbkdf2-sha256$5000$${SALT}$${KEY}`;
    const hasher = pbkdf2Hasher({ iterations: 1000 });
    expect(await Effect.runPromise(hasher.verify("pw", stored))).toBe(true);
    expect(pbkdf2.mock.calls[0]![2]).toBe(5000);
  });

  it.each([
    ["0", 0],
    ["a negative count", -1],
    ["a fraction", 1.5],
    ["NaN", Number.NaN],
    ["Infinity", Number.POSITIVE_INFINITY],
    ["2^31, one past Node's limit", 2 ** 31],
    ["3e9, a safe integer above Node's limit", 3e9],
  ])(
    "hash refuses iterations = %s as a HashingError, before any KDF call",
    async (_label, iterations) => {
      // Node rejects these only when it derives a key, so an unchecked hasher
      // would write a hash that verify cannot read.
      const result = await Effect.runPromise(
        Effect.result(pbkdf2Hasher({ iterations }).hash("pw")),
      );
      expect(result._tag).toBe("Failure");
      if (result._tag === "Failure") {
        expect(result.failure._tag).toBe("HashingError");
      }
      expect(pbkdf2).not.toHaveBeenCalled();
    },
  );
});

describe("pbkdf2 stored iteration limit", () => {
  // A stored hash with the given count. The key is a placeholder: the stub
  // derives a zero key, so an all-zero stored key verifies at any count that
  // is allowed to run.
  const stored = (count: string) => `pbkdf2-sha256$${count}$${SALT}$${KEY}`;

  it.each([
    ["one past the 5,000,000 cap", "5000001"],
    ["Node's largest count, 2^31 - 1", String(2 ** 31 - 1)],
    ["a safe integer above Node's limit", "3000000000"],
  ])(
    "refuses a stored hash with %s as a HashingError before running the KDF",
    async (_label, count) => {
      const hash = stored(count);
      const result = await Effect.runPromise(Effect.result(pbkdf2Hasher().verify("pw", hash)));
      expect(result._tag).toBe("Failure");
      if (result._tag === "Failure") {
        expect(result.failure._tag).toBe("HashingError");
      }
      // Refused before any derivation: an unguarded verify would run PBKDF2 at
      // this count, minutes of CPU at the top of the range.
      expect(pbkdf2).not.toHaveBeenCalled();
      expect(pbkdf2Hasher().needsRehash!(hash)).toBe(true);
    },
  );

  it("verifies a stored count at the 5,000,000 cap", async () => {
    expect(await Effect.runPromise(pbkdf2Hasher().verify("pw", stored("5000000")))).toBe(true);
    expect(pbkdf2.mock.calls[0]![2]).toBe(5000000);
  });

  it("a configured count above the cap still verifies its own hashes", async () => {
    // The cap follows the configured count, so the hasher's own hashes verify,
    // as scrypt's cap follows its configured cost.
    const hasher = pbkdf2Hasher({ iterations: 6000000 });
    const hashed = await Effect.runPromise(hasher.hash("pw"));
    expect(hashed.hash.startsWith("pbkdf2-sha256$6000000$")).toBe(true);
    expect(await Effect.runPromise(hasher.verify("pw", hashed.hash))).toBe(true);
    expect(pbkdf2.mock.calls[1]![2]).toBe(6000000);
    // A hasher with the default cap still refuses that stored count.
    const defaultCap = await Effect.runPromise(
      Effect.result(pbkdf2Hasher().verify("pw", hashed.hash)),
    );
    expect(defaultCap._tag).toBe("Failure");
    expect(pbkdf2).toHaveBeenCalledTimes(2);
  });

  it.each([
    ["NaN", Number.NaN],
    ["Infinity", Number.POSITIVE_INFINITY],
    ["a fraction", 1.5],
    ["a safe integer above Node's limit", 3e9],
    ["2^31, one past Node's limit", 2 ** 31],
  ])(
    "a non-finite or unusable configured count (%s) does not lift the cap",
    async (_label, iterations) => {
      // The cap is max(5,000,000, the configured count) only for a usable
      // configured count; for any other value it stays at 5,000,000.
      const hasher = pbkdf2Hasher({ iterations });
      for (const count of ["5000001", String(2 ** 31 - 1), "3000000000"]) {
        const result = await Effect.runPromise(Effect.result(hasher.verify("pw", stored(count))));
        expect(result._tag).toBe("Failure");
        if (result._tag === "Failure") {
          expect(result.failure._tag).toBe("HashingError");
        }
      }
      expect(pbkdf2).not.toHaveBeenCalled();
    },
  );
});
