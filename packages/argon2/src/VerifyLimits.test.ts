/**
 * The verify ceiling (#752): a stored hash whose `m`, `t` or `p` exceeds
 * `maxMemoryKiB`, `maxIterations` or `maxParallelism` is refused with a
 * `HashingError` before the kernel is entered, so it grows no wasm memory.
 *
 * The kernel's `verifyArgon2` is wrapped in a spy that still runs the real
 * kernel, so each test can say whether verify reached it.
 */
import { assert, beforeEach, describe, expect, it, vi } from "vite-plus/test";
import { Effect } from "effect";
import * as Arr from "effect/Array";
import { Password } from "@thomasfosterau/effect-auth";
import { hashWasmFixtures } from "./HashWasm.fixtures.ts";
import * as Argon2 from "./index.ts";
import { verifyArgon2 } from "./Wasm.ts";

vi.mock("./Wasm.ts", async (importOriginal) => {
  const actual = await importOriginal<typeof import("./Wasm.ts")>();
  return {
    ...actual,
    verifyArgon2: vi.fn<typeof actual.verifyArgon2>(actual.verifyArgon2),
  };
});

const kernel = vi.mocked(verifyArgon2);

beforeEach(() => {
  kernel.mockClear();
});

const run = <A, E>(effect: Effect.Effect<A, E>): Promise<A> => Effect.runPromise(effect);

/** A well-formed stored hash with the given header; its salt and digest are a fixture's. */
const stored = (m: number, t: number, p: number): string =>
  `$argon2id$v=19$m=${m},t=${t},p=${p}$MDEyMzQ1Njc4OWFiY2RlZg$gy5SuVm5Z7Vw7keB9se9p87QGcomaseB/S2U1OhTsM0`;

/** Hash `password` at `costs` and verify it with `verifier`. */
const roundtrip = async (
  costs: Argon2.Argon2Options,
  verifier: typeof Password.PasswordHasher.Service,
): Promise<boolean> => {
  const { hash } = await run(Argon2.argon2Hasher(costs).hash("at the ceiling"));
  return run(verifier.verify("at the ceiling", hash));
};

describe("the default verify ceiling", () => {
  it("is maxMemoryKiB 131072, maxIterations 10, maxParallelism 8", () => {
    expect(Argon2.defaultVerifyLimits).toEqual({
      maxMemoryKiB: 131072,
      maxIterations: 10,
      maxParallelism: 8,
    });
    expect(Argon2.resolveVerifyLimits()).toEqual(Argon2.defaultVerifyLimits);
  });

  it("sits at or above both profiles, so every hash this package writes verifies", () => {
    const { maxMemoryKiB, maxIterations, maxParallelism } = Argon2.defaultVerifyLimits;
    const within = ({ memoryCost, timeCost, parallelism }: Argon2.Argon2Profile) =>
      memoryCost <= maxMemoryKiB && timeCost <= maxIterations && parallelism <= maxParallelism;
    expect(within(Argon2.defaultProfile)).toBe(true);
    expect(within(Argon2.serverProfile)).toBe(true);
  });

  it.each([
    ["m one over maxMemoryKiB", stored(131073, 1, 1), /m=131073 is over maxMemoryKiB=131072/],
    ["m of 4 TiB", stored(2 ** 32 - 1, 1, 1), /over maxMemoryKiB=131072/],
    ["t one over maxIterations", stored(256, 11, 1), /t=11 is over maxIterations=10/],
    ["t of four billion", stored(256, 4_000_000_000, 1), /over maxIterations=10/],
    ["p one over maxParallelism", stored(256, 1, 9), /p=9 is over maxParallelism=8/],
    ["p of 2^24 - 1", stored(256, 1, 2 ** 24 - 1), /over maxParallelism=8/],
  ])("refuses a stored hash with %s, without entering the kernel", async (_, hash, message) => {
    const error = await run(Effect.flip(Argon2.argon2Hasher().verify("x", hash)));
    expect(error._tag).toBe("HashingError");
    expect(error.message).toMatch(/exceeds the verify ceiling/);
    expect(error.message).toMatch(message);
    expect(kernel).not.toHaveBeenCalled();
  });

  it("checks the ceiling after the password guards: an over-long password is still false", async () => {
    const verdict = await run(
      Argon2.argon2Hasher().verify("x".repeat(1025), stored(2 ** 32 - 1, 1, 1)),
    );
    expect(verdict).toBe(false);
    expect(kernel).not.toHaveBeenCalled();
  });

  it.each([
    ["m = maxMemoryKiB (128 MiB)", { memoryCost: 131072, timeCost: 1, parallelism: 1 }],
    ["t = maxIterations", { memoryCost: 256, timeCost: 10, parallelism: 1 }],
    ["p = maxParallelism", { memoryCost: 256, timeCost: 1, parallelism: 8 }],
  ] as const)(
    "verifies a hash at the limit: %s",
    async (_, costs) => {
      expect(await roundtrip(costs, Argon2.argon2Hasher())).toBe(true);
      expect(kernel).toHaveBeenCalledOnce();
    },
    30_000,
  );

  it.each(hashWasmFixtures)("still verifies the hash-wasm fixture: $label", async (fixture) => {
    expect(await run(Argon2.argon2Hasher().verify(fixture.password, fixture.hash))).toBe(true);
    expect(kernel).toHaveBeenCalledOnce();
  });
});

describe("a configured verify ceiling", () => {
  it("lowers each limit", async () => {
    const strict = Argon2.argon2Hasher({
      memoryCost: 256,
      timeCost: 1,
      maxMemoryKiB: 1024,
      maxIterations: 2,
      maxParallelism: 1,
    });
    const cases = [stored(2048, 1, 1), stored(256, 3, 1), stored(256, 1, 2)];
    const messages = await run(
      Effect.forEach(
        cases,
        (hash) => Effect.map(Effect.flip(strict.verify("x", hash)), ({ message }) => message),
        { concurrency: 1 },
      ),
    );
    expect(messages).toEqual([
      "Argon2 hash exceeds the verify ceiling: m=2048 is over maxMemoryKiB=1024",
      "Argon2 hash exceeds the verify ceiling: t=3 is over maxIterations=2",
      "Argon2 hash exceeds the verify ceiling: p=2 is over maxParallelism=1",
    ]);
    expect(kernel).not.toHaveBeenCalled();
  });

  it("raises each limit", async () => {
    const raised = { maxMemoryKiB: 262144, maxIterations: 12, maxParallelism: 16 } as const;
    const lenient = Argon2.argon2Hasher(raised);
    const cases = [
      { memoryCost: 131080, timeCost: 1, parallelism: 1 },
      { memoryCost: 256, timeCost: 12, parallelism: 1 },
      { memoryCost: 256, timeCost: 1, parallelism: 16 },
    ];
    // Each is over the default ceiling...
    const defaults = await run(
      Effect.forEach(
        cases,
        (costs) =>
          Effect.map(
            Effect.flip(
              Argon2.argon2Hasher().verify(
                "x",
                stored(costs.memoryCost, costs.timeCost, costs.parallelism),
              ),
            ),
            ({ message }) => message,
          ),
        { concurrency: 1 },
      ),
    );
    expect(defaults).toEqual(Arr.map(cases, () => expect.stringMatching(/verify ceiling/)));
    expect(kernel).not.toHaveBeenCalled();
    // ...and verifies under the raised one.
    const verdicts = await Arr.reduce(
      cases,
      Promise.resolve<ReadonlyArray<boolean>>([]),
      async (previous, costs) => [
        ...(await previous),
        await roundtrip({ ...costs, ...raised }, lenient),
      ],
    );
    expect(verdicts).toEqual([true, true, true]);
    expect(kernel).toHaveBeenCalledTimes(3);
  });

  it("applies through the layer", async () => {
    const error = await run(
      Effect.provide(
        Effect.flip(
          Effect.gen(function* () {
            const hasher = yield* Password.PasswordHasher;
            return yield* hasher.verify("x", stored(2048, 1, 1));
          }),
        ),
        Argon2.argon2HasherLayer({ memoryCost: 256, timeCost: 1, maxMemoryKiB: 1024 }),
      ),
    );
    expect(error.message).toMatch(/m=2048 is over maxMemoryKiB=1024/);
    expect(kernel).not.toHaveBeenCalled();
  });

  it("refuses, at construction, costs over the ceiling: their hashes would not verify", () => {
    expect(() => Argon2.argon2Hasher({ memoryCost: 262144 })).toThrow(
      new RangeError(
        "Argon2 memoryCost=262144 is over maxMemoryKiB=131072: its hashes would not verify",
      ),
    );
    expect(() => Argon2.argon2Hasher({ timeCost: 3, maxIterations: 2 })).toThrow(
      /timeCost=3 is over maxIterations=2/,
    );
    expect(() => Argon2.argon2HasherLayer({ parallelism: 9 })).toThrow(
      /parallelism=9 is over maxParallelism=8/,
    );
    expect(() => Argon2.argon2Hasher({ memoryCost: 262144, maxMemoryKiB: 262144 })).not.toThrow();
    expect(() => Argon2.argon2Hasher(Argon2.serverProfile)).not.toThrow();
  });

  it.each(
    Arr.flatMap(
      [
        "memoryCost",
        "timeCost",
        "parallelism",
        "maxMemoryKiB",
        "maxIterations",
        "maxParallelism",
      ] as const,
      (limit) =>
        Arr.map(
          [0, -1, 1.5, Number.NaN, Number.POSITIVE_INFINITY],
          (value) => [limit, value] as const,
        ),
    ),
  )("refuses %s = %s at construction", (limit, value) => {
    expect(() => Argon2.argon2Hasher({ [limit]: value })).toThrow(
      new RangeError(`Argon2 ${limit} must be a positive integer, got ${value}`),
    );
  });
});

/** A stored hash with `parameters` as its cost segment; its salt and digest are a fixture's. */
const withParameters = (parameters: string): string =>
  `$argon2id$v=19$${parameters}$MDEyMzQ1Njc4OWFiY2RlZg$gy5SuVm5Z7Vw7keB9se9p87QGcomaseB/S2U1OhTsM0`;

describe("a stored hash the ceiling cannot read is refused before the kernel", () => {
  it.each([
    ["a repeated m (last-wins would read 256)", "m=4294967295,m=256,t=2,p=1", /repeated parameter/],
    ["a repeated t", "m=256,t=2,t=1,p=1", /repeated parameter/],
    ["an unknown parameter", "m=256,t=2,p=1,x=1", /unknown parameter "x"/],
    ["a keyid parameter", "m=256,t=2,p=1,keyid=abc", /unknown parameter "keyid"/],
    ["a parameter with two '='", "m=256=1,t=2,p=1", /malformed parameter "m=256=1"/],
    ["m=+1", "m=+1,t=2,p=1", /malformed parameters/],
    ["m=1e3", "m=1e3,t=2,p=1", /malformed parameters/],
    ["hex m", "m=0x100,t=2,p=1", /malformed parameters/],
    ["m=131072abc", "m=131072abc,t=2,p=1", /malformed parameters/],
    ["a leading space", "m= 256,t=2,p=1", /malformed parameters/],
    ["a trailing space", "m=256 ,t=2,p=1", /malformed parameters/],
    ["m=0", "m=0,t=2,p=1", /malformed parameters/],
    ["t=0", "m=256,t=0,p=1", /malformed parameters/],
    ["a missing p", "m=256,t=2", /malformed parameters/],
    ["an empty value", "m=,t=2,p=1", /malformed parameters/],
  ])("%s", async (_, parameters, message) => {
    const error = await run(
      Effect.flip(Argon2.argon2Hasher().verify("x", withParameters(parameters))),
    );
    expect(error._tag).toBe("HashingError");
    expect(error.message).toMatch(/^Invalid Argon2 hash: /);
    expect(error.message).toMatch(message);
    expect(kernel).not.toHaveBeenCalled();
  });

  it("refuses a stored hash over 512 characters without copying it into the kernel", async () => {
    const hasher = Argon2.argon2Hasher();
    const fixture = hashWasmFixtures[0];
    assert(fixture !== undefined, "a hash-wasm fixture exists");
    const padded = (length: number) => `${fixture.hash}${"A".repeat(length - fixture.hash.length)}`;

    const cases = [padded(513), padded(4 * 1024 * 1024)];
    const messages = await run(
      Effect.forEach(
        cases,
        (hash) => Effect.map(Effect.flip(hasher.verify(fixture.password, hash)), (e) => e.message),
        { concurrency: 1 },
      ),
    );
    expect(messages).toEqual(
      Arr.map(cases, () => "Invalid Argon2 hash: longer than 512 characters"),
    );
    expect(kernel).not.toHaveBeenCalled();

    // At 512 the string reaches the kernel, which reports the padded digest as
    // unverifiable: the cap is on length only.
    const error = await run(Effect.flip(hasher.verify(fixture.password, padded(512))));
    expect(error.message).toMatch(/cannot be recomputed/);
    expect(kernel).toHaveBeenCalledOnce();
  });
});
