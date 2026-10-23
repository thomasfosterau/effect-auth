import { describe, it, expect, vi, beforeEach } from "vite-plus/test";
import { argon2id } from "hash-wasm";
import { Effect } from "effect";
import { Password } from "@thomasfosterau/effect-auth";
import * as Argon2 from "./index.ts";

// Pins the costs the hasher hands the KDF for the default and server profiles
// without running a 19 MiB or 64 MiB derivation: `argon2id` is replaced by a
// stub that records its options and answers at once. The round-trip tests in
// `index.test.ts` run the real KDF at a cheap explicit cost, so neither file
// depends on how fast the machine is (#270).
vi.mock("hash-wasm", async (importOriginal) => {
  const actual = await importOriginal<typeof import("hash-wasm")>();
  return {
    ...actual,
    argon2id: vi.fn(async () => "$argon2id$v=19$m=1,t=1,p=1$c2FsdA$aGFzaA"),
  };
});

const kdf = vi.mocked(argon2id);

beforeEach(() => {
  kdf.mockClear();
});

const expectCosts = (costs: Argon2.Argon2Profile) => {
  expect(kdf).toHaveBeenCalledOnce();
  expect(kdf.mock.calls[0]?.[0]).toMatchObject({
    memorySize: costs.memoryCost,
    iterations: costs.timeCost,
    parallelism: costs.parallelism,
    hashLength: 32,
    outputType: "encoded",
  });
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
    const program = Effect.gen(function* () {
      const hasher = yield* Password.PasswordHasher;
      return yield* hasher.hash("through-the-layer");
    });
    await Effect.runPromise(Effect.provide(program, Argon2.argon2HasherLayer()));
    expectCosts({ memoryCost: 19456, timeCost: 2, parallelism: 1 });
  });
});
