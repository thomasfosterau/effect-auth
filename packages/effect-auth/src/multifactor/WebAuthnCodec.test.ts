import { assert, describe, it, expect } from "vite-plus/test";
import { Array as Arr, Schema } from "effect";
import {
  AttestationObjectParseError,
  AuthenticatorDataParseError,
  CBORParseError,
  ClientDataParseError,
  ClientDataType,
  COSEPublicKey,
  coseAlgorithmES256,
  decodeCBOR,
  decodeCBORNoLeftoverBytes,
  decodeCOSEPublicKey,
  parseAttestationObject,
  parseAuthenticatorData,
  parseClientDataJSON,
  type CBORMap,
} from "./WebAuthnCodec.ts";
import * as Cipher from "../Cipher.ts";

// --- Minimal deterministic CBOR encoder, for building fixtures --------------

const cborHead = (major: number, n: number): number[] => {
  const type = major << 5;
  if (n < 24) return [type | n];
  if (n < 256) return [type | 24, n];
  if (n < 65536) return [type | 25, (n >> 8) & 0xff, n & 0xff];
  return [type | 26, (n >>> 24) & 0xff, (n >>> 16) & 0xff, (n >>> 8) & 0xff, n & 0xff];
};
const cborUint = (n: number): number[] => cborHead(0, n);
const cborNegInt = (n: number): number[] => cborHead(1, -1 - n);
const cborBytes = (b: Uint8Array): number[] => [...cborHead(2, b.length), ...b];
const cborText = (s: string): number[] => {
  const b = Buffer.from(s, "utf8");
  return [...cborHead(3, b.length), ...b];
};
const cborArray = (elements: ReadonlyArray<number[]>): number[] => {
  return [...cborHead(4, elements.length), ...Arr.flatten(elements)];
};
const cborMap = (entries: ReadonlyArray<readonly [number[], number[]]>): number[] => {
  return [...cborHead(5, entries.length), ...Arr.flatMap(entries, ([k, v]) => [...k, ...v])];
};

const bytes = (...values: number[]): Uint8Array => new Uint8Array(values);

const concatBytes = (...arrays: Uint8Array[]): Uint8Array => {
  const total = arrays.reduce((sum, a) => sum + a.length, 0);
  const out = new Uint8Array(total);
  Arr.reduce(arrays, 0, (offset, a) => {
    out.set(a, offset);
    return offset + a.length;
  });
  return out;
};

// --- CBOR --------------------------------------------------------------------

/** Decode `data`, which the test built as a CBOR map. */
const decodeMap = (data: Uint8Array): CBORMap => {
  const decoded = decodeCBORNoLeftoverBytes(data);
  assert(decoded instanceof Map, "the bytes decode to a CBOR map");
  return decoded;
};

describe("CBOR decoding", () => {
  it("decodes integers, byte strings, text strings, arrays, and maps", () => {
    const encoded = new Uint8Array(
      cborMap([
        [cborText("fmt"), cborText("none")],
        [cborUint(1), cborUint(2)],
        [cborNegInt(-1), cborBytes(bytes(1, 2, 3))],
        [cborText("list"), cborArray([cborUint(1), cborNegInt(-7), cborText("x")])],
      ]),
    );
    const decoded = decodeMap(encoded);
    expect(decoded).toBeInstanceOf(Map);
    expect(decoded.get("fmt")).toBe("none");
    // Integer keys are stringified, matching the COSE label convention.
    expect(decoded.get("1")).toBe(2);
    expect(decoded.get("-1")).toEqual(bytes(1, 2, 3));
    expect(decoded.get("list")).toEqual([1, -7, "x"]);
  });

  it("decodes multi-byte lengths and 64-bit integers", () => {
    const big = new Uint8Array(300).fill(7);
    const [decoded] = decodeCBOR(new Uint8Array(cborBytes(big)));
    expect(decoded).toEqual(big);

    // 0x1b = uint64 argument, larger than Number.MAX_SAFE_INTEGER.
    const [huge] = decodeCBOR(bytes(0x1b, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff));
    expect(huge).toBe(18446744073709551615n);
  });

  it("reports how many bytes an item consumed and tolerates trailing bytes", () => {
    const encoded = concatBytes(new Uint8Array(cborUint(1)), bytes(0xaa, 0xbb));
    const [value, size] = decodeCBOR(encoded);
    expect(value).toBe(1);
    expect(size).toBe(1);
  });

  it("rejects leftover bytes when they are not allowed", () => {
    const encoded = concatBytes(new Uint8Array(cborUint(1)), bytes(0xaa));
    expect(() => decodeCBORNoLeftoverBytes(encoded)).toThrow(CBORParseError);
  });

  it("rejects empty input", () => {
    expect(() => decodeCBOR(new Uint8Array(0))).toThrow(CBORParseError);
  });

  it("rejects truncated byte strings", () => {
    // Claims 10 bytes, supplies 2.
    expect(() => decodeCBOR(bytes(0x4a, 0x01, 0x02))).toThrow(CBORParseError);
  });

  it("rejects a truncated map (missing value)", () => {
    expect(() => decodeCBOR(bytes(0xa1, 0x01))).toThrow(CBORParseError);
  });

  it("rejects indefinite-length items", () => {
    expect(() => decodeCBOR(bytes(0x5f, 0x41, 0x01, 0xff))).toThrow(CBORParseError); // bytes
    expect(() => decodeCBOR(bytes(0x9f, 0x01, 0xff))).toThrow(CBORParseError); // array
    expect(() => decodeCBOR(bytes(0xbf, 0x01, 0x01, 0xff))).toThrow(CBORParseError); // map
  });

  it("rejects reserved additional information and floats", () => {
    expect(() => decodeCBOR(bytes(0x1c))).toThrow(CBORParseError); // reserved
    expect(() => decodeCBOR(bytes(0xf9, 0x3c, 0x00))).toThrow(CBORParseError); // float16
    expect(() => decodeCBOR(bytes(0xfb, 0, 0, 0, 0, 0, 0, 0, 0))).toThrow(CBORParseError); // float64
  });

  it("decodes the simple values WebAuthn payloads can contain", () => {
    expect(decodeCBORNoLeftoverBytes(bytes(0xf4))).toBe(false);
    expect(decodeCBORNoLeftoverBytes(bytes(0xf5))).toBe(true);
    expect(decodeCBORNoLeftoverBytes(bytes(0xf6))).toBe(null);
    expect(decodeCBORNoLeftoverBytes(bytes(0xf7))).toBe(undefined);
  });

  it("rejects duplicate map keys", () => {
    const encoded = new Uint8Array(
      cborMap([
        [cborUint(1), cborUint(2)],
        [cborUint(1), cborUint(3)],
      ]),
    );
    expect(() => decodeCBOR(encoded)).toThrow(CBORParseError);
  });

  it("rejects non-scalar map keys", () => {
    const encoded = new Uint8Array(cborMap([[cborArray([cborUint(1)]), cborUint(2)]]));
    expect(() => decodeCBOR(encoded)).toThrow(CBORParseError);
  });

  it("rejects invalid UTF-8 in text strings", () => {
    expect(() => decodeCBOR(bytes(0x62, 0xff, 0xfe))).toThrow(CBORParseError);
  });

  it("bounds nesting depth", () => {
    const nest = (depth: number): number[] =>
      depth === 0 ? cborUint(0) : cborArray([nest(depth - 1)]);
    expect(decodeCBORNoLeftoverBytes(new Uint8Array(nest(4)))).toEqual([[[[0]]]]);
    expect(() => decodeCBOR(new Uint8Array(nest(5)))).toThrow(CBORParseError);
  });

  it("unwraps tagged values", () => {
    // Tag 1 (epoch time) wrapping the integer 5.
    expect(decodeCBORNoLeftoverBytes(bytes(0xc1, 0x05))).toBe(5);
  });
});

// --- COSE public keys --------------------------------------------------------

type Alg = -7 | -257 | -8;

const keyGenParams = (alg: Alg) =>
  alg === -7
    ? { name: "ECDSA", namedCurve: "P-256" }
    : alg === -257
      ? {
          name: "RSASSA-PKCS1-v1_5",
          modulusLength: 2048,
          publicExponent: new Uint8Array([1, 0, 1]),
          hash: "SHA-256",
        }
      : { name: "Ed25519" };

// The public JWK members each key type exports.
const Ec2Jwk = Schema.Struct({ x: Schema.String, y: Schema.String });
const RsaJwk = Schema.Struct({ n: Schema.String, e: Schema.String });
const OkpJwk = Schema.Struct({ x: Schema.String });

/** Generate a keypair and the CBOR bytes of its COSE_Key representation. */
const buildKey = async (
  alg: Alg,
  algorithmLabel: number = alg,
): Promise<{ privateKey: CryptoKey; cose: number[] }> => {
  const keyPair = await globalThis.crypto.subtle.generateKey(keyGenParams(alg), true, [
    "sign",
    "verify",
  ]);
  // Every algorithm `keyGenParams` names is asymmetric, so the result is a pair.
  assert("privateKey" in keyPair, `${alg} generates a key pair`);
  const { publicKey, privateKey } = keyPair;

  if (alg === -7) {
    const jwk = Schema.decodeUnknownSync(Ec2Jwk)(
      await globalThis.crypto.subtle.exportKey("jwk", publicKey),
    );
    return {
      privateKey,
      cose: cborMap([
        [cborUint(1), cborUint(2)],
        [cborUint(3), cborNegInt(algorithmLabel)],
        [cborNegInt(-1), cborUint(1)],
        [cborNegInt(-2), cborBytes(new Uint8Array(Buffer.from(jwk.x, "base64url")))],
        [cborNegInt(-3), cborBytes(new Uint8Array(Buffer.from(jwk.y, "base64url")))],
      ]),
    };
  }
  if (alg === -257) {
    const jwk = Schema.decodeUnknownSync(RsaJwk)(
      await globalThis.crypto.subtle.exportKey("jwk", publicKey),
    );
    return {
      privateKey,
      cose: cborMap([
        [cborUint(1), cborUint(3)],
        [cborUint(3), cborNegInt(algorithmLabel)],
        [cborNegInt(-1), cborBytes(new Uint8Array(Buffer.from(jwk.n, "base64url")))],
        [cborNegInt(-2), cborBytes(new Uint8Array(Buffer.from(jwk.e, "base64url")))],
      ]),
    };
  }
  const jwk = Schema.decodeUnknownSync(OkpJwk)(
    await globalThis.crypto.subtle.exportKey("jwk", publicKey),
  );
  return {
    privateKey,
    cose: cborMap([
      [cborUint(1), cborUint(1)],
      [cborUint(3), cborNegInt(algorithmLabel)],
      [cborNegInt(-1), cborUint(6)],
      [cborNegInt(-2), cborBytes(new Uint8Array(Buffer.from(jwk.x, "base64url")))],
    ]),
  };
};

describe("COSE public keys", () => {
  it("decodes an ES256 key and exposes its parameters", async () => {
    const { cose } = await buildKey(-7);
    const [key, size] = decodeCOSEPublicKey(new Uint8Array(cose));
    expect(size).toBe(cose.length);
    expect(key.algorithm()).toBe(coseAlgorithmES256);
    expect(key.isAlgorithmDefined()).toBe(true);
    const ec2 = key.ec2();
    expect(ec2.curve).toBe(1);
    expect(ec2.x).toBeTypeOf("bigint");
    expect(ec2.y).toBeTypeOf("bigint");
    expect(() => key.rsa()).toThrow("Expected an RSA public key");
    expect(() => key.okp()).toThrow("Expected an octet key pair public key");
  });

  it("decodes RS256 and EdDSA keys", async () => {
    const rsa = decodeCOSEPublicKey(new Uint8Array((await buildKey(-257)).cose))[0].rsa();
    expect(rsa.e).toBe(65537n);
    expect(rsa.n).toBeTypeOf("bigint");

    const okp = decodeCOSEPublicKey(new Uint8Array((await buildKey(-8)).cose))[0].okp();
    expect(okp.curve).toBe(6);
    expect(okp.x.byteLength).toBe(32);
  });

  it("stops at the end of the key, ignoring trailing extension bytes", async () => {
    const { cose } = await buildKey(-7);
    const withTrailer = concatBytes(new Uint8Array(cose), bytes(0xaa, 0xbb, 0xcc));
    const [key, size] = decodeCOSEPublicKey(withTrailer);
    expect(size).toBe(cose.length);
    expect(key.algorithm()).toBe(coseAlgorithmES256);
  });

  it("surfaces an unsupported algorithm label rather than guessing", async () => {
    // -35 is ES384, which effect-auth does not support.
    const { cose } = await buildKey(-7, -35);
    const [key] = decodeCOSEPublicKey(new Uint8Array(cose));
    expect(key.algorithm()).toBe(-35);
  });

  it("rejects malformed CBOR and non-map keys", () => {
    expect(() => decodeCOSEPublicKey(bytes(0x5f))).toThrow("Failed to decode CBOR");
    expect(() => decodeCOSEPublicKey(new Uint8Array(cborUint(1)))).toThrow("Invalid CBOR map");
  });

  it("rejects keys missing or misdeclaring required parameters", () => {
    const missingAlg = new COSEPublicKey(
      decodeMap(new Uint8Array(cborMap([[cborUint(1), cborUint(2)]]))),
    );
    expect(() => missingAlg.algorithm()).toThrow("Invalid or missing parameter 'alg'");
    expect(missingAlg.isAlgorithmDefined()).toBe(false);

    const unknownKty = new COSEPublicKey(
      decodeMap(new Uint8Array(cborMap([[cborUint(1), cborUint(9)]]))),
    );
    expect(() => unknownKty.type()).toThrow("Unknown 'kty' value");

    // EC2 key with a 31-byte x coordinate.
    const shortX = new COSEPublicKey(
      decodeMap(
        new Uint8Array(
          cborMap([
            [cborUint(1), cborUint(2)],
            [cborUint(3), cborNegInt(-7)],
            [cborNegInt(-1), cborUint(1)],
            [cborNegInt(-2), cborBytes(new Uint8Array(31))],
            [cborNegInt(-3), cborBytes(new Uint8Array(32))],
          ]),
        ),
      ),
    );
    expect(() => shortX.ec2()).toThrow("Invalid or missing parameter 'x'");
  });
});

// --- clientDataJSON ----------------------------------------------------------

const encodeJsonString = Schema.encodeSync(Schema.fromJsonString(Schema.Json));

const encodeJson = (value: Schema.Json): Uint8Array =>
  new Uint8Array(Buffer.from(encodeJsonString(value), "utf8"));

describe("parseClientDataJSON", () => {
  it("parses a registration client data blob", () => {
    const challenge = new Uint8Array([1, 2, 3, 4, 5]);
    const parsed = parseClientDataJSON(
      encodeJson({
        type: "webauthn.create",
        challenge: Buffer.from(challenge).toString("base64url"),
        origin: "https://example.com",
        crossOrigin: false,
      }),
    );
    expect(parsed.type).toBe(ClientDataType.Create);
    expect(parsed.challenge).toEqual(challenge);
    expect(parsed.origin).toBe("https://example.com");
    expect(parsed.crossOrigin).toBe(false);
    expect(parsed.tokenBinding).toBe(null);
  });

  it("parses an authentication client data blob and its token binding", () => {
    const parsed = parseClientDataJSON(
      encodeJson({
        type: "webauthn.get",
        challenge: "AQIDBA",
        origin: "https://example.com",
        tokenBinding: { id: "AQID", status: "present" },
      }),
    );
    expect(parsed.type).toBe(ClientDataType.Get);
    expect(parsed.challenge).toEqual(new Uint8Array([1, 2, 3, 4]));
    expect(parsed.tokenBinding?.status).toBe(1);
    expect(parsed.tokenBinding?.id).toEqual(new Uint8Array([1, 2, 3]));
  });

  it("accepts padded base64url challenges", () => {
    const parsed = parseClientDataJSON(
      encodeJson({
        type: "webauthn.get",
        challenge: "AQIDBA==",
        origin: "https://example.com",
      }),
    );
    expect(parsed.challenge).toEqual(new Uint8Array([1, 2, 3, 4]));
  });

  it("rejects invalid JSON", () => {
    expect(() => parseClientDataJSON(bytes(0x7b, 0x7b))).toThrow(ClientDataParseError);
    expect(() => parseClientDataJSON(new Uint8Array(0))).toThrow(
      "Failed to parse client data: Invalid client data JSON",
    );
  });

  it("rejects a non-object payload", () => {
    expect(() => parseClientDataJSON(encodeJson(null))).toThrow(ClientDataParseError);
    expect(() => parseClientDataJSON(encodeJson("string"))).toThrow(ClientDataParseError);
  });

  it("rejects an unknown or missing type", () => {
    expect(() =>
      parseClientDataJSON(encodeJson({ challenge: "AQID", origin: "https://example.com" })),
    ).toThrow("Missing or invalid property 'type'");
    expect(() =>
      parseClientDataJSON(
        encodeJson({ type: "webauthn.other", challenge: "AQID", origin: "https://example.com" }),
      ),
    ).toThrow("Missing or invalid property 'type'");
  });

  it("rejects a challenge that is not valid base64url", () => {
    expect(() =>
      parseClientDataJSON(
        encodeJson({ type: "webauthn.get", challenge: "not+base64url/", origin: "https://x" }),
      ),
    ).toThrow("Missing or invalid property 'challenge'");
    expect(() =>
      parseClientDataJSON(encodeJson({ type: "webauthn.get", challenge: 1, origin: "https://x" })),
    ).toThrow("Missing or invalid property 'challenge'");
  });

  it("rejects a missing origin and a non-boolean crossOrigin", () => {
    expect(() =>
      parseClientDataJSON(encodeJson({ type: "webauthn.get", challenge: "AQID" })),
    ).toThrow("Missing or invalid property 'origin'");
    expect(() =>
      parseClientDataJSON(
        encodeJson({
          type: "webauthn.get",
          challenge: "AQID",
          origin: "https://x",
          crossOrigin: "yes",
        }),
      ),
    ).toThrow("Invalid property 'crossOrigin'");
  });

  it("rejects a malformed token binding", () => {
    expect(() =>
      parseClientDataJSON(
        encodeJson({
          type: "webauthn.get",
          challenge: "AQID",
          origin: "https://x",
          tokenBinding: { id: "AQID", status: "bogus" },
        }),
      ),
    ).toThrow("Missing or invalid property 'tokenBinding.status'");
  });
});

// --- Authenticator data ------------------------------------------------------

const RP_ID = "example.com";
const rpIdHash = Cipher.sha256(new TextEncoder().encode(RP_ID));

const signCounter = (counter: number): Uint8Array =>
  new Uint8Array([
    (counter >>> 24) & 0xff,
    (counter >>> 16) & 0xff,
    (counter >>> 8) & 0xff,
    counter & 0xff,
  ]);

/** Assemble authenticator data with optional attested credential data. */
const authData = (
  flags: number,
  counter: number,
  attested?: { credentialId: Uint8Array; cose: number[] },
): Uint8Array =>
  concatBytes(
    rpIdHash,
    new Uint8Array([flags]),
    signCounter(counter),
    ...(attested
      ? [
          new Uint8Array(16),
          new Uint8Array([
            (attested.credentialId.length >> 8) & 0xff,
            attested.credentialId.length & 0xff,
          ]),
          attested.credentialId,
          new Uint8Array(attested.cose),
        ]
      : []),
  );

describe("parseAuthenticatorData", () => {
  it("parses flags, counter, and relying-party ID hash", () => {
    const parsed = parseAuthenticatorData(authData(0x05, 42));
    expect(parsed.userPresent).toBe(true);
    expect(parsed.userVerified).toBe(true);
    expect(parsed.signatureCounter).toBe(42);
    expect(parsed.credential).toBe(null);
    expect(parsed.relyingPartyIdHash).toEqual(rpIdHash);
    expect(parsed.verifyRelyingPartyIdHash(RP_ID)).toBe(true);
    expect(parsed.verifyRelyingPartyIdHash("evil.example")).toBe(false);
  });

  it("reads user-presence and user-verification flags independently", () => {
    expect(parseAuthenticatorData(authData(0x00, 0)).userPresent).toBe(false);
    expect(parseAuthenticatorData(authData(0x01, 0)).userVerified).toBe(false);
    expect(parseAuthenticatorData(authData(0x04, 0)).userPresent).toBe(false);
    expect(parseAuthenticatorData(authData(0x04, 0)).userVerified).toBe(true);
  });

  it("decodes large counters without sign overflow", () => {
    expect(parseAuthenticatorData(authData(0x01, 0xffffffff)).signatureCounter).toBe(4294967295);
  });

  it("parses attested credential data", async () => {
    const { cose } = await buildKey(-7);
    const credentialId = new Uint8Array([9, 8, 7, 6, 5]);
    const parsed = parseAuthenticatorData(authData(0x45, 0, { credentialId, cose }));
    expect(parsed.credential?.id).toEqual(credentialId);
    expect(parsed.credential?.authenticatorAAGUID).toEqual(new Uint8Array(16));
    expect(parsed.credential?.publicKey.algorithm()).toBe(coseAlgorithmES256);
  });

  it("rejects truncated authenticator data", () => {
    expect(() => parseAuthenticatorData(new Uint8Array(36))).toThrow(AuthenticatorDataParseError);
    expect(() => parseAuthenticatorData(new Uint8Array(36))).toThrow(
      "Failed to parse authenticator data: Insufficient bytes",
    );
    expect(() => parseAuthenticatorData(new Uint8Array(0))).toThrow(AuthenticatorDataParseError);
  });

  it("rejects an attested-credential-data flag with no credential data", () => {
    expect(() => parseAuthenticatorData(authData(0x45, 0))).toThrow("Invalid credential data");
  });

  it("rejects a credential ID longer than the remaining bytes", async () => {
    const { cose } = await buildKey(-7);
    const full = authData(0x45, 0, { credentialId: new Uint8Array([1, 2, 3]), cose });
    // Overstate the credential ID length (bytes 53–54).
    full[53] = 0xff;
    full[54] = 0xff;
    expect(() => parseAuthenticatorData(full)).toThrow(
      "Failed to parse authenticator data: Insufficient bytes",
    );
  });

  it("rejects attested credential data whose public key is not valid CBOR", () => {
    const broken = authData(0x45, 0, {
      credentialId: new Uint8Array([1, 2, 3]),
      // 0x5f is an indefinite-length byte string, which the decoder rejects.
      cose: [0x5f],
    });
    expect(() => parseAuthenticatorData(broken)).toThrow(
      "Failed to parse authenticator data: Failed to parse public key",
    );
  });
});

// --- Attestation objects -----------------------------------------------------

const attestationObject = (fmt: string, data: Uint8Array): Uint8Array =>
  new Uint8Array(
    cborMap([
      [cborText("fmt"), cborText(fmt)],
      [cborText("attStmt"), cborMap([])],
      [cborText("authData"), cborBytes(data)],
    ]),
  );

describe("parseAttestationObject", () => {
  it("parses a none-format attestation object", async () => {
    const { cose } = await buildKey(-7);
    const credentialId = new Uint8Array([4, 3, 2, 1]);
    const parsed = parseAttestationObject(
      attestationObject("none", authData(0x45, 0, { credentialId, cose })),
    );
    expect(parsed.format).toBe(6); // AttestationStatementFormat.None
    expect(parsed.attestationStatement.size).toBe(0);
    expect(parsed.authenticatorData.credential?.id).toEqual(credentialId);
  });

  it("parses a packed attestation statement, leaving it undecoded", async () => {
    const { cose } = await buildKey(-7);
    const encoded = new Uint8Array(
      cborMap([
        [cborText("fmt"), cborText("packed")],
        [
          cborText("attStmt"),
          cborMap([
            [cborText("alg"), cborNegInt(-7)],
            [cborText("sig"), cborBytes(bytes(1, 2, 3))],
            [cborText("x5c"), cborArray([cborBytes(bytes(4, 5, 6))])],
          ]),
        ],
        [
          cborText("authData"),
          cborBytes(authData(0x45, 0, { credentialId: new Uint8Array([1]), cose })),
        ],
      ]),
    );
    const parsed = parseAttestationObject(encoded);
    expect(parsed.format).toBe(0); // Packed
    expect(parsed.attestationStatement.get("alg")).toBe(-7);
    expect(parsed.attestationStatement.get("sig")).toEqual(bytes(1, 2, 3));
    expect(parsed.attestationStatement.get("x5c")).toEqual([bytes(4, 5, 6)]);
  });

  it("rejects malformed CBOR", () => {
    expect(() => parseAttestationObject(bytes(0xff, 0xff, 0xff))).toThrow(
      AttestationObjectParseError,
    );
    expect(() => parseAttestationObject(bytes(0xff, 0xff, 0xff))).toThrow(
      "Failed to parse attestation object: Invalid CBOR data",
    );
    expect(() => parseAttestationObject(new Uint8Array(0))).toThrow(AttestationObjectParseError);
  });

  it("rejects trailing bytes after the attestation object", () => {
    const encoded = concatBytes(attestationObject("none", authData(0x05, 0)), bytes(0x00));
    expect(() => parseAttestationObject(encoded)).toThrow("Invalid CBOR data");
  });

  it("rejects a non-map payload", () => {
    expect(() => parseAttestationObject(new Uint8Array(cborUint(1)))).toThrow("Invalid CBOR data");
  });

  it("rejects an unsupported attestation statement format", () => {
    expect(() => parseAttestationObject(attestationObject("bogus", authData(0x05, 0)))).toThrow(
      "Unsupported attestation statement format 'bogus'",
    );
  });

  it("rejects missing fmt, attStmt, and authData members", () => {
    const noAuthData = new Uint8Array(
      cborMap([
        [cborText("fmt"), cborText("none")],
        [cborText("attStmt"), cborMap([])],
      ]),
    );
    expect(() => parseAttestationObject(noAuthData)).toThrow(
      "Invalid or missing property 'authData'",
    );

    const noAttStmt = new Uint8Array(
      cborMap([
        [cborText("fmt"), cborText("none")],
        [cborText("authData"), cborBytes(authData(0x05, 0))],
      ]),
    );
    expect(() => parseAttestationObject(noAttStmt)).toThrow(
      "Invalid or missing property 'attStmt'",
    );

    const noFmt = new Uint8Array(
      cborMap([
        [cborText("attStmt"), cborMap([])],
        [cborText("authData"), cborBytes(authData(0x05, 0))],
      ]),
    );
    expect(() => parseAttestationObject(noFmt)).toThrow("Invalid or missing property 'fmt'");
  });

  it("propagates authenticator-data errors", () => {
    expect(() => parseAttestationObject(attestationObject("none", new Uint8Array(10)))).toThrow(
      AuthenticatorDataParseError,
    );
  });
});

// --- Signature verification --------------------------------------------------

describe("assertion signature verification", () => {
  it("rejects a corrupted ES256 signature over the assertion message", async () => {
    const { privateKey, cose } = await buildKey(-7);
    const [key] = decodeCOSEPublicKey(new Uint8Array(cose));
    const ec2 = key.ec2();
    const toBytes = (value: bigint, length: number): Uint8Array => {
      const hex = value.toString(16).padStart(length * 2, "0");
      return new Uint8Array(Arr.makeBy(length, (i) => parseInt(hex.slice(i * 2, i * 2 + 2), 16)));
    };
    const spki = Cipher.jwkToSpkiDer({
      kty: "EC",
      crv: "P-256",
      x: Buffer.from(toBytes(ec2.x, 32)).toString("base64url"),
      y: Buffer.from(toBytes(ec2.y, 32)).toString("base64url"),
    });

    const message = concatBytes(authData(0x05, 1), Cipher.sha256(bytes(1, 2, 3)));
    const raw = new Uint8Array(
      await globalThis.crypto.subtle.sign(
        { name: "ECDSA", hash: "SHA-256" },
        privateKey,
        new Uint8Array(message),
      ),
    );
    // Authenticators emit DER; Web Crypto emits raw r||s.
    const derInteger = (value: Uint8Array): Uint8Array => {
      const firstNonZero = value.findIndex((b) => b !== 0);
      const start = Math.max(0, firstNonZero === -1 ? value.length - 1 : firstNonZero);
      const trimmed = value.subarray(start);
      const content =
        ((trimmed[0] ?? 0) & 0x80) !== 0 ? concatBytes(bytes(0), trimmed) : new Uint8Array(trimmed);
      return concatBytes(bytes(0x02, content.length), content);
    };
    const body = concatBytes(derInteger(raw.subarray(0, 32)), derInteger(raw.subarray(32, 64)));
    const der = concatBytes(bytes(0x30, body.length), body);

    expect(Cipher.verifyDerSignature("sha256", spki, message, der)).toBe(true);

    // Flip a bit in the message: the same signature must no longer verify.
    const tampered = new Uint8Array(message);
    tampered[0] = (tampered[0] ?? 0) ^ 0x01;
    expect(Cipher.verifyDerSignature("sha256", spki, tampered, der)).toBe(false);
  });
});
