/**
 * The kernel against the hashes this package wrote before #744 and against
 * `@thomasfosterau/argon2`, whose wasm it embeds.
 */
import { createHash } from "node:crypto";
import { readFile } from "node:fs/promises";
import { assert, describe, expect, it } from "vite-plus/test";
import { hashPassword, verifyPassword } from "@thomasfosterau/argon2";
import { Effect } from "effect";
import * as Arr from "effect/Array";
import * as Result from "effect/Result";
import * as Schema from "effect/Schema";
import { hashWasmFixtures } from "./HashWasm.fixtures.ts";
import * as Argon2 from "./index.ts";
import { hashArgon2id, verifyArgon2 } from "./Wasm.ts";
import { WASM_BASE64, WASM_SHA256, WASM_SOURCE_VERSION } from "./WasmBinary.ts";

const run = <A, E>(effect: Effect.Effect<A, E>): Promise<A> => Effect.runPromise(effect);

const cheap = { memoryCost: 256, timeCost: 1, parallelism: 1 } as const;

/** The `m`/`t`/`p` a PHC header carries. */
const costsOf = (hash: string): Argon2.Argon2Profile => {
  const [, m, t, p] = /\$m=(\d+),t=(\d+),p=(\d+)\$/.exec(hash) ?? [];
  return { memoryCost: Number(m), timeCost: Number(t), parallelism: Number(p) };
};

/**
 * The source of `src/WasmBinary.ts`: the installed devDependency at the exact
 * catalog pin, and the file in it that holds the wasm as `WASM_BASE64`.
 */
const SOURCE = new URL("../node_modules/@thomasfosterau/argon2/", import.meta.url);
const SOURCE_FILE = "dist/index.js";
const REGENERATE = "regenerate it with `vpx scripts/generate-argon2-wasm.ts`";

const Manifest = Schema.fromJsonString(Schema.Struct({ version: Schema.String }));

describe(`the embedded binary (@thomasfosterau/argon2/${SOURCE_FILE} @ ${WASM_SOURCE_VERSION})`, () => {
  it("records the installed devDependency's version", async () => {
    const manifest = Schema.decodeSync(Manifest)(
      await readFile(new URL("package.json", SOURCE), "utf8"),
    );
    expect(manifest.version, `src/WasmBinary.ts is stale: ${REGENERATE}`).toBe(WASM_SOURCE_VERSION);
  });

  it("holds that release's bytes, with the recorded SHA-256", async () => {
    const source = await readFile(new URL(SOURCE_FILE, SOURCE), "utf8");
    const published = /const WASM_BASE64 = "([A-Za-z0-9+/=]+)";/.exec(source)?.[1];
    assert(published !== undefined, `${SOURCE_FILE} holds a WASM_BASE64 constant`);
    const installed = Buffer.from(published, "base64");
    const embedded = Buffer.from(WASM_BASE64, "base64");

    expect(createHash("sha256").update(installed).digest("hex")).toBe(WASM_SHA256);
    expect(createHash("sha256").update(embedded).digest("hex")).toBe(WASM_SHA256);
    expect(embedded.equals(installed), `src/WasmBinary.ts differs: ${REGENERATE}`).toBe(true);
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

describe("concurrency", () => {
  // One instance serves every fiber; each kernel call runs from `alloc` to
  // `dealloc` without yielding, so concurrent fibers can only interleave
  // between calls, never inside one.
  const hasher = Argon2.argon2Hasher(cheap);
  const passwords = Arr.makeBy(24, (index) => `password-${index} ✓`);

  it("concurrent hashes and verifies all come out right", async () => {
    const hashed = await run(
      Effect.all(
        Arr.map(passwords, (password) => hasher.hash(password)),
        { concurrency: "unbounded" },
      ),
    );
    expect(Arr.dedupe(Arr.map(hashed, ({ hash }) => hash))).toHaveLength(passwords.length);

    const verdicts = await run(
      Effect.all(
        Arr.flatMap(Arr.zip(passwords, hashed), ([password, { hash }]) => [
          hasher.verify(password, hash),
          hasher.verify(`${password}!`, hash),
        ]),
        { concurrency: "unbounded" },
      ),
    );
    expect(verdicts).toEqual(Arr.flatMap(passwords, () => [true, false]));
  });

  it("interleaved hashes and fixture verifies do not disturb each other", async () => {
    const verifier = Argon2.argon2Hasher();
    const results = await run(
      Effect.all(
        Arr.flatMap(hashWasmFixtures, ({ password, hash }, index) => [
          verifier.verify(password, hash),
          Effect.flatMap(hasher.hash(`${password}-${index}`), (hashed) =>
            hasher.verify(`${password}-${index}`, hashed.hash),
          ),
        ]),
        { concurrency: "unbounded" },
      ),
    );
    expect(results).toEqual(
      Arr.map(
        Arr.flatMap(hashWasmFixtures, () => [0, 1]),
        () => true,
      ),
    );
  });
});
