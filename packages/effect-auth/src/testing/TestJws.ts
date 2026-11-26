/**
 * Compact JWS signing and verification through `node:crypto`, independent of
 * `effect/jose`, so tests can play an identity provider and check what the
 * library signs. Internal test support: not exported from `./testing`.
 */
import * as crypto from "node:crypto";
import * as Schema from "effect/Schema";

/** The algorithms the test signer supports. */
export type TestJwsAlgorithm = "ES256" | "EdDSA" | "RS256";

const decodeJwk = Schema.decodeUnknownSync(Schema.Record(Schema.String, Schema.Json));

const generate = (algorithm: TestJwsAlgorithm) =>
  algorithm === "ES256"
    ? crypto.generateKeyPairSync("ec", { namedCurve: "P-256" })
    : algorithm === "EdDSA"
      ? crypto.generateKeyPairSync("ed25519")
      : crypto.generateKeyPairSync("rsa", { modulusLength: 2048 });

/** A fresh key pair: the public key as a JWK, the private key as PKCS#8 PEM. */
export const testJwsKeyPair = (algorithm: TestJwsAlgorithm) => {
  const { publicKey, privateKey } = generate(algorithm);
  return {
    publicKeyJwk: decodeJwk(publicKey.export({ format: "jwk" })),
    privateKeyPem: privateKey.export({ type: "pkcs8", format: "pem" }),
  };
};

const digest = (algorithm: TestJwsAlgorithm): string | null =>
  algorithm === "EdDSA" ? null : "sha256";

/** Sign `data` with a PKCS#8 PEM key; ES256 in the JOSE `r || s` form. */
export const testSignJws = (
  algorithm: TestJwsAlgorithm,
  data: Uint8Array,
  privateKeyPem: string,
): Uint8Array =>
  new Uint8Array(
    crypto.sign(digest(algorithm), data, { key: privateKeyPem, dsaEncoding: "ieee-p1363" }),
  );

/** Verify `signature` over `data` against a public JWK. */
export const testVerifyJws = (
  algorithm: TestJwsAlgorithm,
  data: Uint8Array,
  signature: Uint8Array,
  jwk: Schema.JsonObject,
): boolean =>
  crypto.verify(
    digest(algorithm),
    data,
    { key: jwk, format: "jwk", dsaEncoding: "ieee-p1363" },
    signature,
  );
