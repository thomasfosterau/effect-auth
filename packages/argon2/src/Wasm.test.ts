/**
 * The kernel against the hashes this package wrote before #744 and against
 * `@thomasfosterau/argon2`, whose wasm it embeds.
 */
import { readFile } from "node:fs/promises";
import { describe, expect, it } from "vite-plus/test";
import { hashPassword, verifyPassword } from "@thomasfosterau/argon2";
import { Effect } from "effect";
import * as Result from "effect/Result";
import { hashWasmFixtures } from "./HashWasm.fixtures.ts";
import * as Argon2 from "./index.ts";
import { hashArgon2id, verifyArgon2 } from "./Wasm.ts";
import { WASM_BASE64 } from "./WasmBinary.ts";

const run = <A, E>(effect: Effect.Effect<A, E>): Promise<A> => Effect.runPromise(effect);

const cheap = { memoryCost: 256, timeCost: 1, parallelism: 1 } as const;

/** The `m`/`t`/`p` a PHC header carries. */
const costsOf = (hash: string): Argon2.Argon2Profile => {
  const [, m, t, p] = /\$m=(\d+),t=(\d+),p=(\d+)\$/.exec(hash) ?? [];
  return { memoryCost: Number(m), timeCost: Number(t), parallelism: Number(p) };
};

describe("the embedded binary", () => {
  it("is the wasm of the installed @thomasfosterau/argon2", async () => {
    const source = await readFile(
      new URL("../node_modules/@thomasfosterau/argon2/dist/index.js", import.meta.url),
      "utf8",
    );
    const [, published] = /const WASM_BASE64 = "([A-Za-z0-9+/=]+)";/.exec(source) ?? [];
    // On a bump of the catalog pin, copy that release's `WASM_BASE64` into
    // src/WasmBinary.ts, after checking its ABI (src/lib.rs) is unchanged.
    expect(WASM_BASE64 === published, "src/WasmBinary.ts matches the catalog pin").toBe(true);
  });
});

describe("hashes written by hash-wasm (0.1.x)", () => {
  const hasher = Argon2.argon2Hasher();

  it.each(hashWasmFixtures)("verify: $label", async ({ password, hash }) => {
    expect(await run(hasher.verify(password, hash))).toBe(true);
    expect(await run(hasher.verify(`${password}!`, hash))).toBe(false);
  });

  it.each(hashWasmFixtures.filter((fixture) => fixture.derivable))(
    "are what the kernel derives from the same salt: $label",
    ({ password, salt, hash }) => {
      const derived = hashArgon2id(password, new TextEncoder().encode(salt), costsOf(hash));
      expect(derived).toEqual(Result.succeed(hash));
    },
  );
});

describe("interoperability with @thomasfosterau/argon2", () => {
  it("its hashes verify here", async () => {
    const hash = await hashPassword("correct horse battery staple");
    expect(hash).toMatch(/^\$argon2id\$v=19\$m=19456,t=2,p=1\$/);
    const hasher = Argon2.argon2Hasher();
    expect(await run(hasher.verify("correct horse battery staple", hash))).toBe(true);
    expect(await run(hasher.verify("wrong", hash))).toBe(false);
  });

  it.each([
    ["the default profile", Argon2.defaultProfile],
    ["custom costs", { memoryCost: 1024, timeCost: 3, parallelism: 2 }],
  ] as const)("hashes written here with %s verify there", async (_, costs) => {
    const { hash } = await run(Argon2.argon2Hasher(costs).hash("pässwörd ✓"));
    expect(hash).toContain(`$m=${costs.memoryCost},t=${costs.timeCost},p=${costs.parallelism}$`);
    expect(await verifyPassword({ hash, password: "pässwörd ✓" })).toBe(true);
    expect(await verifyPassword({ hash, password: "wrong" })).toBe(false);
  });
});

describe("the kernel's limits", () => {
  it("emits a 16-byte salt and a 32-byte digest", async () => {
    const { hash } = await run(Argon2.argon2Hasher(cheap).hash("lengths"));
    const [, , , , salt = "", digest = ""] = hash.split("$");
    expect(atob(salt)).toHaveLength(Argon2.SALT_LENGTH);
    expect(atob(digest)).toHaveLength(Argon2.HASH_LENGTH);
  });

  it("fails a hash whose costs it rejects", async () => {
    // Argon2 needs at least 8 KiB per lane.
    const error = await run(
      Effect.flip(Argon2.argon2Hasher({ memoryCost: 8, parallelism: 2 }).hash("x")),
    );
    expect(error._tag).toBe("HashingError");
  });

  const digest = hashWasmFixtures[0]?.hash.split("$")[5] ?? "";

  it.each([
    ["a one-byte salt, below the PHC minimum", `$argon2id$v=19$m=19456,t=2,p=1$YQ$${digest}`],
    ["fewer than 8 KiB per lane", `$argon2id$v=19$m=8,t=2,p=2$MDEyMzQ1Njc4OWFiY2RlZg$${digest}`],
    ["a digest that is not base64", "$argon2id$v=19$m=19456,t=2,p=1$MDEyMzQ1Njc4OWFiY2RlZg$!!!!"],
  ])("fails, never returns false, on a stored hash with %s", async (_, hash) => {
    expect(verifyArgon2("x", hash)).toEqual(Result.succeed("unverifiable"));
    const error = await run(Effect.flip(Argon2.argon2Hasher().verify("x", hash)));
    expect(error.message).toMatch(/Invalid Argon2 hash/);
  });

  it("recovers from a trap: the next call runs on a fresh instance", async () => {
    // 4 GiB of blocks cannot be allocated in 32-bit linear memory, so the
    // Rust side aborts (a wasm trap) rather than returning an error.
    const huge = Argon2.argon2Hasher({ memoryCost: 4 * 1024 * 1024 - 8, timeCost: 1 });
    const error = await run(Effect.flip(huge.hash("trap")));
    expect(error._tag).toBe("HashingError");

    const hasher = Argon2.argon2Hasher(cheap);
    const { hash } = await run(hasher.hash("after the trap"));
    expect(await run(hasher.verify("after the trap", hash))).toBe(true);
  });
});
