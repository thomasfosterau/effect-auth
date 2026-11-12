import { describe, it, expect, vi, beforeEach } from "vite-plus/test";
import { Effect } from "effect";
import * as Result from "effect/Result";
import { Password } from "@thomasfosterau/effect-auth";
import * as Argon2 from "./index.ts";
import { hashArgon2id, type KernelCosts, type KernelError } from "./Wasm.ts";

// Pins the costs the hasher hands the KDF for the default and server profiles
// without running a 19 MiB or 64 MiB derivation: the kernel's `hashArgon2id`
// is replaced by a stub that records its arguments and answers at once. The
// round-trip tests in `index.test.ts` run the real KDF at a cheap explicit
// cost, so neither file depends on how fast the machine is (#270).
vi.mock("./Wasm.ts", async (importOriginal) => {
  const actual = await importOriginal<typeof import("./Wasm.ts")>();
  return {
    ...actual,
    hashArgon2id: vi.fn<
      (password: string, salt: Uint8Array, costs: KernelCosts) => Result.Result<string, KernelError>
    >(() => Result.succeed("$argon2id$v=19$m=1,t=1,p=1$c2FsdA$aGFzaA")),
  };
});

const kdf = vi.mocked(hashArgon2id);

beforeEach(() => {
  kdf.mockClear();
});

const expectCosts = (costs: Argon2.Argon2Profile) => {
  expect(kdf).toHaveBeenCalledOnce();
  const [password, salt, handed] = kdf.mock.calls[0] ?? [];
  expect(password).toBeTypeOf("string");
  expect(salt).toHaveLength(Argon2.SALT_LENGTH);
  expect(handed).toEqual(costs);
};

describe("cost profiles reach the KDF", () => {
  it("argon2Hasher() derives with m = 19456, t = 2, p = 1", async () => {
    await Effect.runPromise(Argon2.argon2Hasher().hash("default-profile"));
    expectCosts({ memoryCost: 19456, timeCost: 2, parallelism: 1 });
  });

  it("argon2Hasher(serverProfile) derives with m = 65536, t = 3, p = 1", async () => {
    await Effect.runPromise(Argon2.argon2Hasher(Argon2.serverProfile).hash("server-profile"));
    expectCosts({ memoryCost: 65536, timeCost: 3, parallelism: 1 });
  });

  it("argon2HasherLayer() uses the default profile", async () => {
    await Effect.runPromise(
      Effect.provide(
        Effect.gen(function* () {
          const hasher = yield* Password.PasswordHasher;
          return yield* hasher.hash("through-the-layer");
        }),
        Argon2.argon2HasherLayer(),
      ),
    );
    expectCosts({ memoryCost: 19456, timeCost: 2, parallelism: 1 });
  });

  it("draws a fresh salt for every hash", async () => {
    const hasher = Argon2.argon2Hasher();
    await Effect.runPromise(hasher.hash("same"));
    await Effect.runPromise(hasher.hash("same"));
    const [first, second] = kdf.mock.calls.map(([, salt]) => salt);
    expect(first).not.toEqual(second);
  });
});
