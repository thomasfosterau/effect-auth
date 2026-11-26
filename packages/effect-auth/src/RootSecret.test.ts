import { createHash, createHmac } from "node:crypto";
import { assert, describe, expect, it } from "vite-plus/test";
import { ConfigProvider, Effect, Exit, Layer, Redacted } from "effect";
import * as Arr from "effect/Array";
import { Hex } from "effect/encoding";
import * as Cipher from "./Cipher.ts";
import * as PlatformCrypto from "./PlatformCrypto.ts";
import {
  MIN_ROOT_SECRET_BYTES,
  pepperHasher,
  pkceVerifier,
  type Encryption,
  type Purpose,
  RootSecret,
  sealerFor,
} from "./RootSecret.ts";
import { testRootSecret } from "./testing/RootSecret.ts";
import { testCryptoLayer, testKey, testPepper } from "./testing/TestCrypto.ts";

const run = <A, E>(effect: Effect.Effect<A, E, PlatformCrypto.Services | RootSecret>) =>
  Effect.runPromise(effect.pipe(Effect.provide(testCryptoLayer)));

const keyOf = (secret: string, purpose: Purpose) =>
  Effect.runPromise(
    RootSecret.use((root) => root.key(purpose)).pipe(Effect.provide(RootSecret.layer(secret))),
  );

describe("RootSecret", () => {
  it("refuses a secret shorter than the minimum", async () => {
    const exit = await Effect.runPromiseExit(
      Effect.provide(
        RootSecret.use(Effect.succeed),
        RootSecret.layer("x".repeat(MIN_ROOT_SECRET_BYTES - 1)),
      ),
    );
    assert(Exit.isFailure(exit));
    expect(String(exit.cause)).toMatch(/RootSecretError/);
  });

  it("builds synchronously, so a services build can finish before its first request", () => {
    const root = Effect.runSync(
      Effect.provide(RootSecret.use(Effect.succeed), RootSecret.layer(testRootSecret)),
    );
    expect(root.key).toBeTypeOf("function");
  });

  it("derives each purpose's key with HKDF-SHA256 under its own info string", async () => {
    const purposes: ReadonlyArray<Purpose> = [
      "otp-pepper",
      "pkce-verifier",
      "totp-secret",
      "oauth-tokens",
      "jwt-private-key",
    ];
    const derived = await Promise.all(
      purposes.map(async (purpose) => [await keyOf(testRootSecret, purpose), testKey(purpose)]),
    );
    expect(derived.map(([key]) => key)).toEqual(derived.map(([, expected]) => expected));
    const hexes = derived.map(([key]) => Hex.encode(key ?? new Uint8Array(0)));
    expect(Arr.dedupe(hexes)).toHaveLength(purposes.length);
  });

  it("reads the secret from AUTH_SECRET, which is required", async () => {
    const withEnv = (env: Record<string, string>) =>
      Effect.runPromiseExit(
        RootSecret.use((root) => root.key("otp-pepper")).pipe(
          Effect.provide(
            RootSecret.layerConfig.pipe(
              Layer.provide(ConfigProvider.layer(ConfigProvider.fromEnv({ env }))),
            ),
          ),
        ),
      );
    const exit = await withEnv({ AUTH_SECRET: testRootSecret });
    assert(Exit.isSuccess(exit));
    expect(exit.value).toEqual(testKey("otp-pepper"));
    expect(Exit.isFailure(await withEnv({}))).toBe(true);
  });
});

describe("pepperHasher", () => {
  it("is HMAC-SHA256 under the pepper key, not a bare digest", async () => {
    const hash = await run(Effect.flatMap(pepperHasher, (pepper) => pepper("123456")));
    expect(hash).toBe(testPepper("123456"));
    expect(hash).not.toBe(createHash("sha256").update("123456").digest("hex"));
  });

  it("differs under another root secret", async () => {
    const other = "fedcba9876543210".repeat(4);
    const hash = await Effect.runPromise(
      Effect.flatMap(pepperHasher, (pepper) => pepper("123456")).pipe(
        Effect.provide(Layer.merge(PlatformCrypto.layer, Layer.orDie(RootSecret.layer(other)))),
      ),
    );
    expect(hash).not.toBe(testPepper("123456"));
  });
});

describe("pkceVerifier", () => {
  it("is a 43-character base64url HMAC of the state under its own key", async () => {
    const verifier = await run(Effect.flatMap(pkceVerifier, (derive) => derive("state-1")));
    expect(verifier).toMatch(/^[A-Za-z0-9_-]{43}$/);
    expect(verifier).toBe(
      createHmac("sha256", testKey("pkce-verifier")).update("state-1").digest("base64url"),
    );
  });
});

describe("sealerFor", () => {
  const seal = (purpose: Purpose, plaintext: string, row: string, encryption?: Encryption) =>
    run(Effect.flatMap(sealerFor(purpose, encryption), (sealer) => sealer.seal(plaintext, row)));
  const open = (purpose: Purpose, stored: string, row: string, encryption?: Encryption) =>
    run(Effect.flatMap(sealerFor(purpose, encryption), (sealer) => sealer.open(stored, row)));

  it("seals in the current format and opens only for the same purpose and row", async () => {
    const sealed = await seal("totp-secret", "JBSWY3DPEHPK3PXP", "user-1");
    expect(sealed.startsWith(Cipher.SEALED_PREFIX)).toBe(true);
    expect(await open("totp-secret", sealed, "user-1")).toBe("JBSWY3DPEHPK3PXP");
    await expect(open("totp-secret", sealed, "user-2")).rejects.toThrow(/Decryption failed/);
    await expect(open("oauth-tokens", sealed, "user-1")).rejects.toThrow(/Decryption failed/);
  });

  it("reads a value stored before encryption as plaintext", async () => {
    expect(await open("totp-secret", "JBSWY3DPEHPK3PXP", "user-1")).toBe("JBSWY3DPEHPK3PXP");
  });

  it("opens an override secret's legacy ciphertext, and seals new values under a key derived from it", async () => {
    const secret = "override-secret-for-totp";
    const encryption = { secret: Redacted.make(secret) };
    const legacy = await run(
      Effect.flatMap(Cipher.aes256GcmCipher(secret), (cipher) =>
        cipher.encrypt("JBSWY3DPEHPK3PXP"),
      ),
    );
    expect(await open("totp-secret", legacy, "user-1", encryption)).toBe("JBSWY3DPEHPK3PXP");

    const sealed = await seal("totp-secret", "JBSWY3DPEHPK3PXP", "user-1", encryption);
    expect(sealed.startsWith(Cipher.SEALED_PREFIX)).toBe(true);
    expect(await open("totp-secret", sealed, "user-1", encryption)).toBe("JBSWY3DPEHPK3PXP");
    // The override's key is not the root secret's.
    await expect(open("totp-secret", sealed, "user-1")).rejects.toThrow(/Decryption failed/);
  });

  it("hands a custom cipher the value unchanged, in its own format", async () => {
    const cipher: Cipher.TokenCipher = {
      encrypt: (plaintext) => Effect.succeed(`custom:${plaintext}`),
      decrypt: (ciphertext) => Effect.succeed(ciphertext.slice("custom:".length)),
    };
    expect(await seal("oauth-tokens", "at-1", "row", { cipher })).toBe("custom:at-1");
    expect(await open("oauth-tokens", "custom:at-1", "row", { cipher })).toBe("at-1");
  });
});
