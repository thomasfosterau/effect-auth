/**
 * The WebCrypto-backed primitives: AES-GCM sealing, HMAC, and the WebAuthn
 * signature check, with Node's `node:crypto` as the independent reference.
 */
import * as crypto from "node:crypto";
import { assert, describe, expect, it } from "vite-plus/test";
import { Effect } from "effect";
import * as Arr from "effect/Array";
import * as Cipher from "./Cipher.ts";
import * as PlatformCrypto from "./PlatformCrypto.ts";

const run = <A, E>(effect: Effect.Effect<A, E, PlatformCrypto.Services>): Promise<A> =>
  Effect.runPromise(PlatformCrypto.provide(effect));

const enc = (text: string): Uint8Array => new TextEncoder().encode(text);

const flipLast = (bytes: Uint8Array): Uint8Array => {
  const copy = new Uint8Array(bytes);
  copy[copy.length - 1] ^= 1;
  return copy;
};

describe("hmac and sha256", () => {
  it("match node:crypto", async () => {
    const reference = crypto.createHmac("sha256", "key").update("data").digest();
    expect(await run(Cipher.hmac("sha256", "key", "data"))).toEqual(new Uint8Array(reference));
    const digest = crypto.createHash("sha256").update("data").digest();
    expect(await run(Cipher.sha256("data"))).toEqual(new Uint8Array(digest));
  });

  it("refuses an empty key", async () => {
    const result = await run(Effect.result(Cipher.hmac("sha256", "", "data")));
    expect(result._tag).toBe("Failure");
  });
});

describe("aes256GcmSeal / aes256GcmOpen", () => {
  it("opens what it sealed, and nothing under another key or tampered", async () => {
    const key = await run(Cipher.sha256("key"));
    const other = await run(Cipher.sha256("other"));
    const sealed = await run(Cipher.aes256GcmSeal(key, "payload"));
    expect(await run(Cipher.aes256GcmOpen(key, sealed))).toBe("payload");
    expect(await run(Cipher.aes256GcmOpen(other, sealed))).toBeNull();
    const tampered = Buffer.from(sealed, "base64url");
    tampered[tampered.length - 1] ^= 1;
    expect(await run(Cipher.aes256GcmOpen(key, tampered.toString("base64url")))).toBeNull();
    expect(await run(Cipher.aes256GcmOpen(key, "dG9vc2hvcnQ"))).toBeNull();
  });

  it("stores iv || tag || ciphertext, which node:crypto opens", async () => {
    const key = await run(Cipher.sha256("key"));
    const sealed = Buffer.from(await run(Cipher.aes256GcmSeal(key, "payload")), "base64url");
    const decipher = crypto.createDecipheriv("aes-256-gcm", key, sealed.subarray(0, 12));
    decipher.setAuthTag(sealed.subarray(12, 28));
    const opened = Buffer.concat([decipher.update(sealed.subarray(28)), decipher.final()]);
    expect(opened.toString("utf8")).toBe("payload");
  });

  it("opens what node:crypto sealed in that layout", async () => {
    const key = await run(Cipher.sha256("key"));
    const iv = crypto.randomBytes(12);
    const cipher = crypto.createCipheriv("aes-256-gcm", key, iv);
    const ct = Buffer.concat([cipher.update("from-node", "utf8"), cipher.final()]);
    const sealed = Buffer.concat([iv, cipher.getAuthTag(), ct]).toString("base64url");
    expect(await run(Cipher.aes256GcmOpen(key, sealed))).toBe("from-node");
  });
});

describe("derToP1363", () => {
  const { publicKey, privateKey } = crypto.generateKeyPairSync("ec", { namedCurve: "P-256" });

  it("gives an r || s that node:crypto verifies as ieee-p1363", () => {
    // Enough signatures that some r or s has its high bit set or is short.
    Arr.forEach(Arr.range(0, 63), (i) => {
      const message = enc(`message-${i}`);
      const p1363 = Cipher.derToP1363(crypto.sign("sha256", message, privateKey), 32);
      assert(p1363 !== undefined && p1363.length === 64);
      expect(
        crypto.verify("sha256", message, { key: publicKey, dsaEncoding: "ieee-p1363" }, p1363),
      ).toBe(true);
    });
  });

  it.each([
    ["an empty input", []],
    ["a non-SEQUENCE tag", [0x31, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01]],
    ["a length that disagrees with the input", [0x30, 0x07, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01]],
    ["trailing bytes after s", [0x30, 0x07, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01, 0x00]],
    ["a negative r", [0x30, 0x06, 0x02, 0x01, 0x81, 0x02, 0x01, 0x01]],
    ["a non-minimal leading zero", [0x30, 0x07, 0x02, 0x02, 0x00, 0x01, 0x02, 0x01, 0x01]],
    ["an empty integer", [0x30, 0x05, 0x02, 0x00, 0x02, 0x01, 0x01]],
    [
      "an r longer than the curve",
      [0x30, 0x26, 0x02, 0x21, ...Arr.replicate(0x11, 33), 0x02, 0x01, 0x01],
    ],
  ])("refuses %s", (_label, bytes) => {
    expect(Cipher.derToP1363(new Uint8Array(bytes), 32)).toBeUndefined();
  });
});

describe("verifySpkiSignature", () => {
  const message = enc("authenticator-data || client-data-hash");

  it("verifies an ES256 DER signature and refuses a tampered one or the raw form", async () => {
    const { publicKey, privateKey } = crypto.generateKeyPairSync("ec", { namedCurve: "P-256" });
    const spki = new Uint8Array(publicKey.export({ format: "der", type: "spki" }));
    const der = new Uint8Array(crypto.sign("sha256", message, privateKey));
    const raw = new Uint8Array(
      crypto.sign("sha256", message, { key: privateKey, dsaEncoding: "ieee-p1363" }),
    );
    expect(await run(Cipher.verifySpkiSignature("ES256", spki, message, der))).toBe(true);
    expect(await run(Cipher.verifySpkiSignature("ES256", spki, flipLast(message), der))).toBe(
      false,
    );
    expect(await run(Cipher.verifySpkiSignature("ES256", spki, message, raw))).toBe(false);
  });

  const rsa = crypto.generateKeyPairSync("rsa", { modulusLength: 2048 });
  const ed = crypto.generateKeyPairSync("ed25519");

  it.each([
    {
      algorithm: "RS256" as const,
      spki: rsa.publicKey.export({ format: "der", type: "spki" }),
      signature: crypto.sign("sha256", message, rsa.privateKey),
    },
    {
      algorithm: "EdDSA" as const,
      spki: ed.publicKey.export({ format: "der", type: "spki" }),
      signature: crypto.sign(null, message, ed.privateKey),
    },
  ])(
    "verifies $algorithm and refuses a tampered signature",
    async ({ algorithm, spki, signature }) => {
      const key = new Uint8Array(spki);
      const sig = new Uint8Array(signature);
      expect(await run(Cipher.verifySpkiSignature(algorithm, key, message, sig))).toBe(true);
      expect(await run(Cipher.verifySpkiSignature(algorithm, key, message, flipLast(sig)))).toBe(
        false,
      );
    },
  );

  it("builds the same SPKI from a JWK as node:crypto", async () => {
    const { publicKey } = crypto.generateKeyPairSync("ec", { namedCurve: "P-256" });
    const { x, y } = publicKey.export({ format: "jwk" });
    assert(x !== undefined && y !== undefined);
    const spki = await run(Cipher.jwkToSpkiDer("ES256", { kty: "EC", crv: "P-256", x, y }));
    expect(spki).toEqual(new Uint8Array(publicKey.export({ format: "der", type: "spki" })));
  });
});
