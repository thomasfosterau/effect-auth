/**
 * The JWS primitives against the implementation they replaced (#748).
 *
 * Before #748, ES256 handed `crypto.sign` / `crypto.verify` a `KeyObject`
 * with `dsaEncoding: "ieee-p1363"`, which workerd rejects; it now hands them
 * the PEM or the JWK. `keyObjectSign` / `keyObjectVerify` below are that
 * implementation, kept only as the reference: in Node, tokens cross both
 * ways, Ed25519 signs the same bytes, and every malformed input fails (or
 * verifies) exactly as it did.
 */
import * as crypto from "node:crypto";
import { describe, expect, it } from "vite-plus/test";
import * as Arr from "effect/Array";
import { Base64Url } from "effect/encoding";
import * as P from "effect/Predicate";
import * as R from "effect/Record";
import * as Result from "effect/Result";
import * as Schema from "effect/Schema";
import * as Cipher from "./Cipher.ts";
import * as Rfc7515 from "./testing/Rfc7515.ts";
import * as Types from "./Types.ts";

/** The pre-#748 `signJws`. */
const keyObjectSign = (
  algorithm: "ES256" | "EdDSA",
  data: Uint8Array,
  privateKeyPem: string,
): Uint8Array => {
  const key = crypto.createPrivateKey(privateKeyPem);
  return algorithm === "EdDSA"
    ? crypto.sign(null, data, key)
    : crypto.sign("sha256", data, { key, dsaEncoding: "ieee-p1363" });
};

/** The pre-#748 `verifyJws`. */
const keyObjectVerify = (
  algorithm: Cipher.JwsAlgorithm,
  data: Uint8Array,
  signature: Uint8Array,
  jwk: Types.JsonObject,
): boolean => {
  const key = crypto.createPublicKey({ key: jwk, format: "jwk" });
  if (algorithm === "RS256") return crypto.verify("sha256", data, key, signature);
  if (algorithm === "ES256")
    return crypto.verify("sha256", data, { key, dsaEncoding: "ieee-p1363" }, signature);
  return crypto.verify(null, data, key, signature);
};

/** What a call did: its value, or that it threw (the message is not compared). */
const outcome = <A>(f: () => A): { readonly value: A } | "threw" =>
  Result.match(
    Result.try(() => f()),
    { onSuccess: (value) => ({ value }), onFailure: () => "threw" as const },
  );

const enc = (text: string): Uint8Array => new TextEncoder().encode(text);

const flipLast = (bytes: Uint8Array): Uint8Array => {
  const copy = new Uint8Array(bytes);
  copy[copy.length - 1] = (copy.at(-1) ?? 0) ^ 1;
  return copy;
};

const decodeJwk = Schema.decodeUnknownSync(Types.JsonObject);
const publicJwk = (key: crypto.KeyObject): Types.JsonObject =>
  decodeJwk(key.export({ format: "jwk" }));

const rsa = crypto.generateKeyPairSync("rsa", { modulusLength: 2048 });
const rsaJwk = publicJwk(rsa.publicKey);
const rsaPem = rsa.privateKey.export({ type: "pkcs8", format: "pem" });

/** Fresh key pairs and payloads for the round trips. */
const ROUNDS = Arr.range(0, 24);
const fixture = (algorithm: "ES256" | "EdDSA", round: number) => ({
  ...Cipher.generateJwsKeyPair(algorithm),
  data: enc(`header.payload-${algorithm}-${round}-${"x".repeat(round * 7)}`),
});

describe("signJws / verifyJws against the KeyObject implementation (#748)", () => {
  describe.each(["ES256", "EdDSA"] as const)("%s", (algorithm) => {
    it.each(ROUNDS)("round %i: a new signature verifies under the old verifier", (round) => {
      const { publicKeyJwk, privateKeyPem, data } = fixture(algorithm, round);
      const signature = Cipher.signJws(algorithm, data, privateKeyPem);
      expect(keyObjectVerify(algorithm, data, signature, publicKeyJwk)).toBe(true);
      expect(Cipher.verifyJws(algorithm, data, signature, publicKeyJwk)).toBe(true);
    });

    it.each(ROUNDS)("round %i: an old signature verifies under the new verifier", (round) => {
      const { publicKeyJwk, privateKeyPem, data } = fixture(algorithm, round);
      const signature = keyObjectSign(algorithm, data, privateKeyPem);
      expect(Cipher.verifyJws(algorithm, data, signature, publicKeyJwk)).toBe(true);
    });

    it("generates a JWK equal to the private key's public export, with no undefined member", () => {
      const { publicKeyJwk, privateKeyPem } = Cipher.generateJwsKeyPair(algorithm);
      expect(R.values(publicKeyJwk).every(P.isNotUndefined)).toBe(true);
      expect(publicKeyJwk).toEqual(publicJwk(crypto.createPublicKey(privateKeyPem)));
    });
  });

  describe("the exported public JWK carries every member its key needs", () => {
    const ec = { kty: "EC", crv: "P-256", x: "x-coordinate", y: "y-coordinate" };
    const okp = { kty: "OKP", crv: "Ed25519", x: "public-key" };

    it("keeps a complete export, dropping its undefined members", () => {
      expect(Cipher.exportedPublicJwk("ES256", { ...ec, alg: undefined })).toEqual(ec);
      expect(Cipher.exportedPublicJwk("EdDSA", { ...okp, use: undefined })).toEqual(okp);
    });

    it.each([
      ["ES256", { ...ec, y: undefined }, "y"],
      ["ES256", { kty: "EC", crv: "P-256" }, "x, y"],
      ["ES256", { ...ec, kty: undefined, crv: undefined }, "kty, crv"],
      ["EdDSA", { ...okp, x: undefined }, "x"],
      ["EdDSA", {}, "kty, crv, x"],
    ] as const)("refuses a %s export lacking a member: %j", (algorithm, exported, missing) => {
      expect(() => Cipher.exportedPublicJwk(algorithm, exported)).toThrow(
        `The exported ${algorithm} public JWK lacks ${missing}`,
      );
    });
  });

  it("verifies RFC 7515 Appendix A.3's ES256 JWS with its published public JWK", () => {
    const [header, payload, signature] = Rfc7515.compactJws.split(".");
    const signingInput = enc(`${header}.${payload}`);
    const bytes = Result.getOrElse(Base64Url.decode(signature ?? ""), () => new Uint8Array(0));
    expect(Cipher.verifyJws("ES256", signingInput, bytes, Rfc7515.publicJwk)).toBe(true);
    expect(Cipher.verifyJws("ES256", signingInput, flipLast(bytes), Rfc7515.publicJwk)).toBe(false);
  });

  it.each(ROUNDS)("round %i: ES256 signatures are raw JOSE r || s, never DER", (round) => {
    const { privateKeyPem, data } = fixture("ES256", round);
    expect(Cipher.signJws("ES256", data, privateKeyPem)).toHaveLength(64);
  });

  it.each(ROUNDS)("round %i: EdDSA signs the bytes the old signer signed", (round) => {
    // Ed25519 is deterministic: the same key signs the same bytes.
    const { privateKeyPem, data } = fixture("EdDSA", round);
    expect([...Cipher.signJws("EdDSA", data, privateKeyPem)]).toEqual([
      ...keyObjectSign("EdDSA", data, privateKeyPem),
    ]);
  });

  it.each(Arr.range(0, 9))("round %i: RS256 verifies as before", (round) => {
    const data = enc(`header.payload-RS256-${round}`);
    const signature = new Uint8Array(crypto.sign("sha256", data, rsa.privateKey));
    expect(Cipher.verifyJws("RS256", data, signature, rsaJwk)).toBe(true);
    expect(keyObjectVerify("RS256", data, signature, rsaJwk)).toBe(true);
  });

  describe("every malformed input ends as it did", () => {
    const ec = Cipher.generateJwsKeyPair("ES256");
    const ed = Cipher.generateJwsKeyPair("EdDSA");
    const data = enc("header.payload");
    const ecSignature = Cipher.signJws("ES256", data, ec.privateKeyPem);
    const edSignature = Cipher.signJws("EdDSA", data, ed.privateKeyPem);
    const rsSignature = new Uint8Array(crypto.sign("sha256", data, rsa.privateKey));
    const ecDer = new Uint8Array(
      crypto.sign("sha256", data, crypto.createPrivateKey(ec.privateKeyPem)),
    );
    const { crv: _crv, ...ecWithoutCurve } = ec.publicKeyJwk;

    const verifyCases: ReadonlyArray<
      readonly [string, Cipher.JwsAlgorithm, Uint8Array, Uint8Array, Types.JsonObject]
    > = [
      ["ES256 valid", "ES256", data, ecSignature, ec.publicKeyJwk],
      ["ES256 tampered data", "ES256", enc("header.payloaD"), ecSignature, ec.publicKeyJwk],
      ["ES256 tampered signature", "ES256", data, flipLast(ecSignature), ec.publicKeyJwk],
      ["ES256 63-byte signature", "ES256", data, ecSignature.subarray(0, 63), ec.publicKeyJwk],
      [
        "ES256 65-byte signature",
        "ES256",
        data,
        new Uint8Array([...ecSignature, 0]),
        ec.publicKeyJwk,
      ],
      ["ES256 empty signature", "ES256", data, new Uint8Array(0), ec.publicKeyJwk],
      ["ES256 DER signature", "ES256", data, ecDer, ec.publicKeyJwk],
      ["ES256 all-zero signature", "ES256", data, new Uint8Array(64), ec.publicKeyJwk],
      ["ES256 against an Ed25519 JWK", "ES256", data, ecSignature, ed.publicKeyJwk],
      ["ES256 against an RSA JWK", "ES256", data, ecSignature, rsaJwk],
      ["ES256 JWK without crv", "ES256", data, ecSignature, ecWithoutCurve],
      [
        "ES256 JWK with a foreign x",
        "ES256",
        data,
        ecSignature,
        { ...ec.publicKeyJwk, x: ed.publicKeyJwk["x"] ?? "" },
      ],
      ["ES256 empty JWK", "ES256", data, ecSignature, {}],
      [
        "ES256 JWK with alg and use",
        "ES256",
        data,
        ecSignature,
        { ...ec.publicKeyJwk, alg: "RS256", use: "enc" },
      ],
      ["EdDSA valid", "EdDSA", data, edSignature, ed.publicKeyJwk],
      ["EdDSA tampered signature", "EdDSA", data, flipLast(edSignature), ed.publicKeyJwk],
      ["EdDSA short signature", "EdDSA", data, edSignature.subarray(0, 32), ed.publicKeyJwk],
      ["EdDSA against a P-256 JWK", "EdDSA", data, edSignature, ec.publicKeyJwk],
      ["EdDSA ES256 signature", "EdDSA", data, ecSignature, ed.publicKeyJwk],
      ["RS256 valid", "RS256", data, rsSignature, rsaJwk],
      ["RS256 tampered signature", "RS256", data, flipLast(rsSignature), rsaJwk],
      ["RS256 against a P-256 JWK", "RS256", data, rsSignature, ec.publicKeyJwk],
      ["RS256 empty signature", "RS256", data, new Uint8Array(0), rsaJwk],
    ];

    it.each(verifyCases)("verify: %s", (_name, algorithm, input, signature, jwk) => {
      expect(outcome(() => Cipher.verifyJws(algorithm, input, signature, jwk))).toEqual(
        outcome(() => keyObjectVerify(algorithm, input, signature, jwk)),
      );
    });

    it("verifies a DER-encoded ES256 signature to false, without throwing", () => {
      expect(Cipher.verifyJws("ES256", data, ecDer, ec.publicKeyJwk)).toBe(false);
    });

    const sec1Pem = crypto
      .createPrivateKey(ec.privateKeyPem)
      .export({ type: "sec1", format: "pem" });

    const refusedKeys: ReadonlyArray<readonly [string, "ES256" | "EdDSA", string]> = [
      ["ES256 with an Ed25519 key", "ES256", ed.privateKeyPem],
      [
        "ES256 with garbage",
        "ES256",
        "-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----",
      ],
      ["ES256 with an empty string", "ES256", ""],
      ["EdDSA with garbage", "EdDSA", "not a key"],
    ];

    it.each(refusedKeys)("sign refuses, as before: %s", (_name, algorithm, pem) => {
      expect(outcome(() => Cipher.signJws(algorithm, data, pem))).toBe("threw");
      expect(outcome(() => keyObjectSign(algorithm, data, pem))).toBe("threw");
    });

    // Neither implementation checks that the key is of the algorithm's type:
    // `crypto.sign` signs with the key's own scheme. JwtService and the Apple
    // client secret only ever pass a key of the right type.
    it("signs a P-256 key under EdDSA, as before", () => {
      expect(outcome(() => Cipher.signJws("EdDSA", data, ec.privateKeyPem))).not.toBe("threw");
      expect(outcome(() => keyObjectSign("EdDSA", data, ec.privateKeyPem))).not.toBe("threw");
    });

    it("signs an RSA key under ES256 with the same PKCS#1 v1.5 bytes as before", () => {
      expect([...Cipher.signJws("ES256", data, rsaPem)]).toEqual([
        ...keyObjectSign("ES256", data, rsaPem),
      ]);
    });

    it("signs with a SEC1 P-256 PEM, as before", () => {
      const jwk = publicJwk(crypto.createPublicKey(sec1Pem));
      expect(keyObjectVerify("ES256", data, Cipher.signJws("ES256", data, sec1Pem), jwk)).toBe(
        true,
      );
      expect(Cipher.verifyJws("ES256", data, keyObjectSign("ES256", data, sec1Pem), jwk)).toBe(
        true,
      );
    });
  });
});
