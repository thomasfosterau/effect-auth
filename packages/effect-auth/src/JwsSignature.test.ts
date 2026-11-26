/**
 * The JWS helpers over `effect/jose` against Node's own signer and verifier,
 * and RFC 7515's published ES256 example.
 */
import { describe, expect, it } from "vite-plus/test";
import * as Effect from "effect/Effect";
import * as Redacted from "effect/Redacted";
import * as Arr from "effect/Array";
import * as Schema from "effect/Schema";
import { Base64Url } from "effect/encoding";
import { jwkSuitsAlgorithm, signWithPkcs8, verifiesWithJwk } from "./JwsSignature.ts";
import * as PlatformCrypto from "./PlatformCrypto.ts";
import * as Rfc7515 from "./testing/Rfc7515.ts";
import {
  testJwsKeyPair,
  testSignJws,
  testVerifyJws,
  type TestJwsAlgorithm,
} from "./testing/TestJws.ts";

const enc = (text: string): Uint8Array => new TextEncoder().encode(text);
const encodeJson = Schema.encodeSync(Schema.fromJsonString(Schema.Unknown));
const decodeJson = Schema.decodeUnknownSync(Schema.fromJsonString(Schema.Unknown));
const b64 = (data: Uint8Array | string): string => Base64Url.encode(data);

type Algorithm = TestJwsAlgorithm;

const keyPairs = {
  ES256: testJwsKeyPair("ES256"),
  EdDSA: testJwsKeyPair("EdDSA"),
  RS256: testJwsKeyPair("RS256"),
};

const publicJwk = (algorithm: Algorithm) => keyPairs[algorithm].publicKeyJwk;
const privatePem = (algorithm: Algorithm) => keyPairs[algorithm].privateKeyPem;

/** A compact JWS Node signs. */
const nodeSigned = (algorithm: Algorithm, claims: object): string => {
  const input = `${b64(encodeJson({ alg: algorithm, typ: "JWT" }))}.${b64(encodeJson(claims))}`;
  return `${input}.${b64(testSignJws(algorithm, enc(input), privatePem(algorithm)))}`;
};

/** Whether Node verifies a compact JWS under the algorithm's public key. */
const nodeVerifies = (algorithm: Algorithm, token: string): boolean => {
  const [header = "", payload = "", signature = ""] = token.split(".");
  return testVerifyJws(
    algorithm,
    enc(`${header}.${payload}`),
    Buffer.from(signature, "base64url"),
    publicJwk(algorithm),
  );
};

const tamper = (token: string): string => {
  const [header, , signature] = token.split(".");
  return `${header}.${b64(encodeJson({ sub: "attacker" }))}.${signature}`;
};

const ALGORITHMS: ReadonlyArray<Algorithm> = ["ES256", "EdDSA", "RS256"];

describe("verifiesWithJwk", () => {
  it("verifies RFC 7515 Appendix A.3's ES256 JWS with its published public JWK", async () => {
    expect(
      await Effect.runPromise(verifiesWithJwk(Rfc7515.compactJws, Rfc7515.publicJwk, "ES256")),
    ).toBe(true);
    expect(
      await Effect.runPromise(
        verifiesWithJwk(tamper(Rfc7515.compactJws), Rfc7515.publicJwk, "ES256"),
      ),
    ).toBe(false);
  });

  it.each(ALGORITHMS)(
    "verifies what Node signs with %s, and refuses it tampered",
    async (algorithm) => {
      const token = nodeSigned(algorithm, { sub: "u-1" });
      const jwk = publicJwk(algorithm);
      expect(await Effect.runPromise(verifiesWithJwk(token, jwk, algorithm))).toBe(true);
      expect(await Effect.runPromise(verifiesWithJwk(tamper(token), jwk, algorithm))).toBe(false);
    },
  );

  it("refuses a token whose header names another algorithm than the key's", async () => {
    const token = nodeSigned("ES256", { sub: "u-1" });
    const [, payload, signature] = token.split(".");
    const relabelled = `${b64(encodeJson({ alg: "RS256" }))}.${payload}.${signature}`;
    expect(await Effect.runPromise(verifiesWithJwk(relabelled, publicJwk("ES256"), "ES256"))).toBe(
      false,
    );
  });

  const signed = nodeSigned("ES256", { sub: "u-1" });
  it.each([
    { name: "a JWK missing its members", token: signed, jwk: { kty: "EC" } },
    {
      name: "a private JWK",
      token: signed,
      jwk: { kty: "EC", crv: "P-256", x: "AAAA", y: "AAAA", d: "AAAA" },
    },
    { name: "a token that is no compact JWS", token: "not.a-jws", jwk: publicJwk("ES256") },
  ])("fails on $name", async ({ token, jwk }) => {
    expect(await Effect.runPromise(Effect.isFailure(verifiesWithJwk(token, jwk, "ES256")))).toBe(
      true,
    );
  });
});

describe("signWithPkcs8", () => {
  it.each(Arr.cartesian(ALGORITHMS, Arr.range(0, 4)))(
    "%s round %i: Node verifies what it signs",
    async (algorithm, round) => {
      const token = await Effect.runPromise(
        signWithPkcs8(enc(encodeJson({ round })), Redacted.make(privatePem(algorithm)), algorithm, {
          kid: "k-1",
          typ: "JWT",
        }).pipe(PlatformCrypto.provide),
      );
      expect(nodeVerifies(algorithm, token)).toBe(true);
      expect(decodeJson(Buffer.from(token.split(".")[0] ?? "", "base64url").toString())).toEqual({
        alg: algorithm,
        kid: "k-1",
        typ: "JWT",
      });
    },
  );

  it("emits ES256 signatures in the raw JOSE r || s form, never DER", async () => {
    const token = await Effect.runPromise(
      signWithPkcs8(enc("{}"), Redacted.make(privatePem("ES256")), "ES256", {}).pipe(
        PlatformCrypto.provide,
      ),
    );
    expect(Buffer.from(token.split(".")[2] ?? "", "base64url")).toHaveLength(64);
  });
});

describe("jwkSuitsAlgorithm", () => {
  const ec = publicJwk("ES256");
  const ed = publicJwk("EdDSA");
  const rsa = publicJwk("RS256");

  it("accepts each algorithm's own key type", () => {
    expect(jwkSuitsAlgorithm("ES256", ec)).toBe(true);
    expect(jwkSuitsAlgorithm("EdDSA", ed)).toBe(true);
    expect(jwkSuitsAlgorithm("RS256", rsa)).toBe(true);
  });

  it.each([
    ["RS256", ec],
    ["RS256", ed],
    ["ES256", rsa],
    ["ES256", ed],
    ["ES256", { ...ec, crv: "P-384" }],
    ["EdDSA", ec],
    ["EdDSA", { ...ed, crv: "X25519" }],
    ["ES256", { ...ec, alg: "RS256" }],
  ] as const)("refuses %s with a mismatched key", (algorithm, jwk) => {
    expect(jwkSuitsAlgorithm(algorithm, jwk)).toBe(false);
  });
});
