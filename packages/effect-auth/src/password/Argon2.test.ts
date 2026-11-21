import { describe, it, expect, assert } from "vite-plus/test";
import * as crypto from "node:crypto";
import { Effect, Exit, Layer } from "effect";
import * as P from "effect/Predicate";
import { Kdf, Password as CryptoPassword, SecureRandom } from "effect/crypto";
import * as PlatformCrypto from "../PlatformCrypto.ts";
import {
  argon2DefaultProfile,
  argon2idHasher,
  argon2idHasherLayer,
  argon2ServerProfile,
  type Argon2Options,
} from "./Argon2.ts";
import { PasswordHasher } from "./Password.ts";

// `node:crypto.argon2` arrived in Node.js 24.7; `NodeCrypto.layerKdf` wraps
// the same call. The derivation cases skip where it is missing.
const hasArgon2 = P.isFunction(crypto.argon2);

/** A `Kdf` deriving Argon2id with `node:crypto`, counting its calls. */
const nodeKdf = () => {
  let calls = 0;
  const kdf: typeof Kdf.Kdf.Service = {
    derive: (algorithm, secret, { salt, length }) =>
      Effect.callback((resume) => {
        calls++;
        if (!("memory" in algorithm)) return resume(Effect.die("argon2id only"));
        crypto.argon2(
          "argon2id",
          {
            message: secret,
            nonce: salt,
            memory: algorithm.memory,
            passes: algorithm.passes,
            parallelism: algorithm.parallelism,
            tagLength: length,
          },
          (error, key) => resume(error ? Effect.die(error) : Effect.succeed(new Uint8Array(key))),
        );
      }),
  };
  return { kdf, calls: () => calls };
};

const cheap: Argon2Options = { memoryCost: 256, timeCost: 1, parallelism: 1 };
/** The `effect/crypto` `Password` service over `kdf`, hashing at the costs in `options`. */
const cryptoPasswords = (kdf: typeof Kdf.Kdf.Service, options?: Argon2Options) => {
  const costs = { ...argon2DefaultProfile, ...options };
  const algorithm = Kdf.argon2id({
    memory: costs.memoryCost,
    passes: costs.timeCost,
    parallelism: costs.parallelism,
  });
  return Effect.runSync(
    Effect.gen(function* () {
      return yield* CryptoPassword.Password;
    }).pipe(
      Effect.provide(
        CryptoPassword.layer({ algorithm }).pipe(
          Layer.provide([
            Layer.succeed(Kdf.Kdf, kdf),
            Layer.succeed(SecureRandom.SecureRandom, PlatformCrypto.instance),
          ]),
        ),
      ),
    ),
  );
};

const hasherWith = (options?: Argon2Options) => {
  const { kdf, calls } = nodeKdf();
  return { hasher: argon2idHasher(cryptoPasswords(kdf, options), options), calls };
};
const run = <A, E>(effect: Effect.Effect<A, E>) => Effect.runPromise(effect);
const runExit = <A, E>(effect: Effect.Effect<A, E>) => Effect.runPromiseExit(effect);

// Written by effect-auth-argon2 (hash-wasm 4.13.0 through 0.1.x, the RustCrypto
// kernel since): stored hashes from that package must keep verifying.
const legacyArgon2id = [
  {
    password: "correct horse battery staple",
    hash: "$argon2id$v=19$m=19456,t=2,p=1$MDEyMzQ1Njc4OWFiY2RlZg$gy5SuVm5Z7Vw7keB9se9p87QGcomaseB/S2U1OhTsM0",
  },
  {
    password: "pässwörd ✓ unicode",
    hash: "$argon2id$v=19$m=1024,t=3,p=2$dW5pY29kZXVuaWNvZGV1bg$ArA6wUYDEk3sakY9qcDxHKIPxwiuTCC14H0jPDlt1gQ",
  },
  {
    password: "pässwörd ✓ unicode",
    hash: "$argon2id$v=19$m=1024,t=3,p=2$MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY$NLXH3ZRWxhs7m+cua/TKcdSN0IuN1va/",
  },
  {
    password: "x",
    hash: "$argon2id$v=19$m=512,t=1,p=1$YWJjZGVmZ2hpamtsbW5vcA$v8f1zungZIxOiVMpZTtXo7oBSR0XYkXoZeFwBXRlXhj5vInkeyzMQXJmS/lrClT5SQxsH7+YSEoa/qnHFGnYPA",
  },
];

describe.skipIf(!hasArgon2)("argon2idHasher derivation", () => {
  it("round-trips and rejects a wrong password", async () => {
    const { hasher } = hasherWith(cheap);
    const { hash, algorithm } = await run(hasher.hash("correct horse"));
    expect(algorithm).toBe("argon2id");
    expect(hash).toMatch(/^\$argon2id\$v=19\$m=256,t=1,p=1\$[A-Za-z0-9+/]{22}\$[A-Za-z0-9+/]{43}$/);
    expect(await run(hasher.verify("correct horse", hash))).toBe(true);
    expect(await run(hasher.verify("correct hors", hash))).toBe(false);
  });

  it("draws a fresh salt for every hash", async () => {
    const { hasher } = hasherWith(cheap);
    const a = await run(hasher.hash("same"));
    const b = await run(hasher.hash("same"));
    expect(a.hash).not.toBe(b.hash);
  });

  it.each(legacyArgon2id)("verifies a stored effect-auth-argon2 hash ($hash)", async (fixture) => {
    const { hasher } = hasherWith();
    expect(await run(hasher.verify(fixture.password, fixture.hash))).toBe(true);
    expect(await run(hasher.verify(`${fixture.password}!`, fixture.hash))).toBe(false);
  });

  it("reads the costs from the stored hash, not the options", async () => {
    const { hasher: writer } = hasherWith(cheap);
    const { hash } = await run(writer.hash("pw"));
    const { hasher: reader } = hasherWith({ memoryCost: 512, timeCost: 2 });
    expect(await run(reader.verify("pw", hash))).toBe(true);
    expect(reader.needsRehash?.(hash)).toBe(true);
    expect(writer.needsRehash?.(hash)).toBe(false);
  });

  it("works as a layer over the Kdf service", async () => {
    const { kdf } = nodeKdf();
    const program = Effect.gen(function* () {
      const hasher = yield* PasswordHasher;
      const { hash } = yield* hasher.hash("pw");
      return yield* hasher.verify("pw", hash);
    }).pipe(
      Effect.provide(argon2idHasherLayer(cheap).pipe(Layer.provide(Layer.succeed(Kdf.Kdf, kdf)))),
    );
    expect(await run(program)).toBe(true);
  });
});

describe("argon2idHasher refusals", () => {
  it("refuses a stored hash over the ceiling before the KDF", async () => {
    const { hasher, calls } = hasherWith();
    const salt = "MDEyMzQ1Njc4OWFiY2RlZg";
    const digest = "gy5SuVm5Z7Vw7keB9se9p87QGcomaseB/S2U1OhTsM0";
    const exits = await Promise.all(
      ["m=4194304,t=2,p=1", "m=19456,t=11,p=1", "m=19456,t=2,p=9"].map((params) =>
        runExit(hasher.verify("pw", `$argon2id$v=19$${params}$${salt}$${digest}`)),
      ),
    );
    expect(exits.every(Exit.isFailure)).toBe(true);
    expect(calls()).toBe(0);
  });

  it.each([
    "$argon2i$v=19$m=4096,t=3,p=1$c2FsdHNhbHRzYWx0c2FsdA$VBRqg4+btGy7IwGibYuU9f0M9kmWU0rIiVedJHJJyHI",
    "$pbkdf2-sha256$i=1000,l=32$MDEyMzQ1Njc4OWFiY2RlZg$gy5SuVm5Z7Vw7keB9se9p87QGcomaseB/S2U1OhTsM0",
    "$argon2id$v=19$m=19456,t=2,p=1$MDEyMzQ1Njc4OWFiY2RlZg$Z3k",
    "$argon2id$v=16$m=19456,t=2,p=1$MDEyMzQ1Njc4OWFiY2RlZg$gy5SuVm5Z7Vw7keB9se9p87QGcomaseB/S2U1OhTsM0",
    "$argon2id$v=19$m=19456,m=1,t=2,p=1$MDEyMzQ1Njc4OWFiY2RlZg$gy5SuVm5Z7Vw7keB9se9p87QGcomaseB/S2U1OhTsM0",
    "$argon2id$v=19$m=19456,t=2,p=1,x=1$MDEyMzQ1Njc4OWFiY2RlZg$gy5SuVm5Z7Vw7keB9se9p87QGcomaseB/S2U1OhTsM0",
    "$argon2id$v=19$m=1e4,t=2,p=1$MDEyMzQ1Njc4OWFiY2RlZg$gy5SuVm5Z7Vw7keB9se9p87QGcomaseB/S2U1OhTsM0",
    "$argon2id$v=19$m=19456,t=2,p=1$c2hvcnQ$gy5SuVm5Z7Vw7keB9se9p87QGcomaseB/S2U1OhTsM0",
    "$argon2id$v=19$m=19456,t=2,p=1$MDEyMzQ1Njc4OWFiY2RlZg==$gy5SuVm5Z7Vw7keB9se9p87QGcomaseB/S2U1OhTsM0",
    "$argon2id$v=19$m=19456,t=2,p=1$MDEyMzQ1Njc4OWFiY2RlZg",
    `$argon2id$v=19$m=19456,t=2,p=1$MDEyMzQ1Njc4OWFiY2RlZg$${"A".repeat(600)}`,
  ])("fails, never returns false, on an unverifiable hash: %s", async (hash) => {
    const { hasher, calls } = hasherWith();
    const exit = await runExit(hasher.verify("pw", hash));
    assert(Exit.isFailure(exit));
    expect(calls()).toBe(0);
    expect(hasher.needsRehash?.(hash)).toBe(true);
  });

  it("refuses empty inputs and caps the password before the KDF", async () => {
    const { hasher, calls } = hasherWith();
    const stored =
      "$argon2id$v=19$m=19456,t=2,p=1$MDEyMzQ1Njc4OWFiY2RlZg$gy5SuVm5Z7Vw7keB9se9p87QGcomaseB/S2U1OhTsM0";
    assert(Exit.isFailure(await runExit(hasher.hash(""))));
    assert(Exit.isFailure(await runExit(hasher.hash("x".repeat(1025)))));
    assert(Exit.isFailure(await runExit(hasher.verify("", stored))));
    assert(Exit.isFailure(await runExit(hasher.verify("pw", ""))));
    expect(await run(hasher.verify("x".repeat(1025), stored))).toBe(false);
    expect(calls()).toBe(0);
  });

  it("throws on a configuration whose hashes would not verify", () => {
    const { kdf } = nodeKdf();
    const make = (options: Argon2Options) => () => argon2idHasher(cryptoPasswords(kdf), options);
    expect(make({ memoryCost: 262144 })).toThrow(RangeError);
    expect(make({ timeCost: 0 })).toThrow(RangeError);
    expect(make({ parallelism: Number.NaN })).toThrow(RangeError);
    expect(make({ maxIterations: 1.5 })).toThrow(RangeError);
    expect(make(argon2ServerProfile)).not.toThrow();
    expect(make(argon2DefaultProfile)).not.toThrow();
  });

  it("fails with a HashingError on a Kdf without Argon2id", async () => {
    const program = Effect.gen(function* () {
      const hasher = yield* PasswordHasher;
      return yield* hasher.hash("pw");
    }).pipe(Effect.provide(argon2idHasherLayer().pipe(Layer.provide(Kdf.layerWebCrypto))));
    const exit = await runExit(program);
    assert(Exit.isFailure(exit));
    expect(String(exit.cause)).toContain("NodeCrypto.layerKdf");
  });
});
