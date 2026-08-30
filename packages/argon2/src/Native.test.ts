import { describe, it, expect } from "vite-plus/test";
import { Effect } from "effect";
import { Password } from "@thomasfosterau/effect-auth";
import * as Argon2 from "./index.ts";
import * as Native from "./Native.ts";

const run = <A, E>(effect: Effect.Effect<A, E>): Promise<A> => Effect.runPromise(effect);

/**
 * `@node-rs/argon2` is an optional peer dependency, so the native suites only
 * run where it is actually installed (it is a devDependency of this package,
 * so they do run in CI).
 */
const nativeInstalled = await import("@node-rs/argon2").then(
  () => true,
  () => false,
);

describe.skipIf(!nativeInstalled)("Native.nativeArgon2Hasher", () => {
  it("hashes and verifies a password (roundtrip)", async () => {
    const hasher = Native.nativeArgon2Hasher();
    const { hash, algorithm } = await run(hasher.hash("correct horse battery staple"));
    expect(algorithm).toBe(Argon2.ARGON2ID);
    expect(await run(hasher.verify("correct horse battery staple", hash))).toBe(true);
  });

  it("rejects a wrong password", async () => {
    const hasher = Native.nativeArgon2Hasher();
    const { hash } = await run(hasher.hash("the-real-password"));
    expect(await run(hasher.verify("not-the-password", hash))).toBe(false);
  });

  it("emits the same PHC shape and defaults as the WASM hasher", async () => {
    const { hash } = await run(Native.nativeArgon2Hasher().hash("phc-shape"));
    expect(hash).toMatch(/^\$argon2id\$v=19\$m=19456,t=2,p=1\$[^$]+\$[^$]+$/);
  });

  it("honours custom cost parameters in the PHC header", async () => {
    const { hash } = await run(
      Native.nativeArgon2Hasher({ memoryCost: 8192, timeCost: 3, parallelism: 2 }).hash("costs"),
    );
    expect(hash).toContain("$m=8192,t=3,p=2$");
  });

  it("fails on an empty password", async () => {
    const err = await run(Effect.flip(Native.nativeArgon2Hasher().hash("")));
    expect(err.message).toMatch(/non-empty/);
  });

  it("provides the PasswordHasher service through its layer", async () => {
    const program = Effect.gen(function* () {
      const hasher = yield* Password.PasswordHasher;
      const { hash } = yield* hasher.hash("through-the-native-layer");
      return yield* hasher.verify("through-the-native-layer", hash);
    });

    expect(await run(Effect.provide(program, Native.nativeArgon2HasherLayer()))).toBe(true);
  });
});

describe.skipIf(!nativeInstalled)("native <-> WASM cross-compatibility", () => {
  it("verifies a natively produced hash with the WASM hasher", async () => {
    const native = Native.nativeArgon2Hasher();
    const wasm = Argon2.argon2Hasher();

    const { hash } = await run(native.hash("cross-compat-secret"));
    expect(await run(wasm.verify("cross-compat-secret", hash))).toBe(true);
    expect(await run(wasm.verify("wrong", hash))).toBe(false);
  });

  it("verifies a WASM-produced hash with the native hasher", async () => {
    const native = Native.nativeArgon2Hasher();
    const wasm = Argon2.argon2Hasher();

    const { hash } = await run(wasm.hash("cross-compat-secret"));
    expect(await run(native.verify("cross-compat-secret", hash))).toBe(true);
    expect(await run(native.verify("wrong", hash))).toBe(false);
  });

  it("crosses backends when the stored hash uses non-default cost parameters", async () => {
    const options = { memoryCost: 8192, timeCost: 1, parallelism: 1 } as const;
    const native = Native.nativeArgon2Hasher(options);
    const wasm = Argon2.argon2Hasher(options);

    // Both hashers are configured with the OWASP defaults on the reading side,
    // so verification must come from the parameters in the PHC string.
    const nativeHash = (await run(native.hash("legacy-costs"))).hash;
    const wasmHash = (await run(wasm.hash("legacy-costs"))).hash;

    expect(await run(Argon2.argon2Hasher().verify("legacy-costs", nativeHash))).toBe(true);
    expect(await run(Native.nativeArgon2Hasher().verify("legacy-costs", wasmHash))).toBe(true);
  });

  it("produces byte-identical digests for the same password, salt and costs", async () => {
    // A fixed salt makes Argon2id deterministic, so both backends must agree
    // on the digest itself, not just on each other's verify().
    const wasmHash = (await run(Argon2.argon2Hasher().hash("determinism"))).hash;
    const salt = wasmHash.split("$")[4]!;

    const argon2 = await import("@node-rs/argon2");
    const nativeHash = await argon2.hash("determinism", {
      memoryCost: 19456,
      timeCost: 2,
      parallelism: 1,
      salt: Buffer.from(salt, "base64"),
    });

    expect(nativeHash).toBe(wasmHash);
  });
});

describe("Native module shape", () => {
  it("re-exports the shared cost profiles", () => {
    expect(Native.defaultProfile).toEqual(Argon2.defaultProfile);
    expect(Native.serverProfile).toEqual(Argon2.serverProfile);
  });

  it("does not import @node-rs/argon2 from the WASM entry point", async () => {
    // The default entry point must stay free of the native module so bundlers
    // targeting Cloudflare Workers never try to resolve it.
    const [{ readFile }, { fileURLToPath }] = await Promise.all([
      import("node:fs/promises"),
      import("node:url"),
    ]);
    const dir = fileURLToPath(new URL(".", import.meta.url));
    for (const file of ["index.ts", "Argon2.ts", "Common.ts"]) {
      const source = await readFile(`${dir}${file}`, "utf8");
      // Doc comments may mention the package; an import of it must not exist.
      expect(source).not.toMatch(/(?:from|import\()\s*"@node-rs\/argon2"/);
    }
  });
});
