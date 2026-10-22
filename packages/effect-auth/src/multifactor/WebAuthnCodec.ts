/**
 * WebAuthn wire-format decoding: CBOR, `clientDataJSON`, authenticator data,
 * attestation objects, and COSE public keys.
 *
 * This module exists so the core package keeps `effect` as its only runtime
 * dependency — it replaces the parsing subset effect-auth previously took from
 * a third-party WebAuthn package, matching that library's validation rules and
 * error messages so the surrounding service contract is unchanged.
 *
 * Nothing here performs signature verification: assertion signatures are
 * verified in `Cipher.ts` against the SPKI DER public key stored at
 * registration.
 *
 * @module webauthn-codec
 */

import { Array as Arr, Data, Match, Option, Predicate, Result, Schema } from "effect";
import { sha256 } from "../Cipher.ts";
import { timingSafeEqualBytes } from "../TokenHash.ts";

// ---------------------------------------------------------------------------
// CBOR (RFC 8949) — the definite-length subset WebAuthn uses
// ---------------------------------------------------------------------------

/** A decoded CBOR map. Integer keys are stringified (`-1` → `"-1"`). */
export type CBORMap = ReadonlyMap<string, CBORValue>;

/** Any value the decoder can produce. */
export type CBORValue =
  | number
  | bigint
  | string
  | Uint8Array
  | boolean
  | null
  | undefined
  | readonly CBORValue[]
  | CBORMap;

/** Thrown for any input this decoder rejects. */
export class CBORParseError extends Error {
  constructor(message: string) {
    super(`Failed to decode CBOR: ${message}`);
    this.name = "CBORParseError";
  }
}

/**
 * Thrown by the {@link COSEPublicKey} accessors, {@link decodeCOSEPublicKey}
 * and the base64url decoder for input they reject.
 */
class CodecError extends Data.TaggedError("CodecError")<{ readonly message: string }> {}

/** The indices `0, 1, …, count - 1` (empty when `count` is 0). */
const indices = (count: number): ReadonlyArray<number> =>
  Array.from({ length: count }, (_, index) => index);

/** Big-endian unsigned integer from bytes. */
const bigIntFromBytes = (bytes: Uint8Array): bigint =>
  Arr.reduce(bytes, 0n, (value, byte) => (value << 8n) | BigInt(byte));

/**
 * Maximum nesting depth. CTAP2 attestation objects nest at most three levels
 * (`attestationObject` → `attStmt` → `x5c` → certificate), so four is ample
 * and bounds the work a hostile authenticator response can cause.
 */
const MAX_CBOR_DEPTH = 4;

const MAX_SAFE = BigInt(Number.MAX_SAFE_INTEGER);
const MIN_SAFE = BigInt(Number.MIN_SAFE_INTEGER);

/** Integers become `number` when exactly representable, `bigint` otherwise. */
const narrowInteger = (value: bigint): number | bigint =>
  value <= MAX_SAFE && value >= MIN_SAFE ? Number(value) : value;

const utf8 = new TextDecoder("utf-8", { fatal: true });

/** Read the argument that follows a CBOR head byte. Returns `[value, next]`. */
const readArgument = (
  data: Uint8Array,
  offset: number,
  additionalInformation: number,
): readonly [bigint, number] => {
  if (additionalInformation < 24) return [BigInt(additionalInformation), offset + 1];
  const size =
    additionalInformation === 24
      ? 1
      : additionalInformation === 25
        ? 2
        : additionalInformation === 26
          ? 4
          : additionalInformation === 27
            ? 8
            : 0;
  if (size === 0) {
    // 28–30 are reserved; 31 is the indefinite-length form, which CTAP2
    // canonical CBOR forbids.
    throw new CBORParseError("Unsupported or reserved additional information");
  }
  if (data.byteLength < offset + 1 + size) {
    throw new CBORParseError("Insufficient bytes");
  }
  return [bigIntFromBytes(data.subarray(offset + 1, offset + 1 + size)), offset + 1 + size];
};

/** Read a definite length/count argument as a bounded JS number. */
const readLength = (data: Uint8Array, offset: number, additionalInformation: number) => {
  const [raw, next] = readArgument(data, offset, additionalInformation);
  if (raw > BigInt(data.byteLength)) {
    // Every length/count is bounded by the remaining input: a byte string
    // needs that many bytes, and an array/map needs at least one byte per item.
    throw new CBORParseError("Insufficient bytes");
  }
  return [Number(raw), next] as const;
};

/** Decode one CBOR data item at `offset`. Returns `[value, nextOffset]`. */
const decodeItem = (
  data: Uint8Array,
  offset: number,
  depth: number,
): readonly [CBORValue, number] => {
  if (depth > MAX_CBOR_DEPTH) throw new CBORParseError("Maximum depth exceeded");
  // `offset` is a non-negative integer, so this is `data.byteLength < offset + 1`.
  const head = data[offset];
  if (head === undefined) throw new CBORParseError("Insufficient bytes");

  const majorType = head >> 5;
  const additionalInformation = head & 0x1f;

  return Match.value(majorType).pipe(
    Match.withReturnType<readonly [CBORValue, number]>(),
    Match.when(0, () => {
      const [value, next] = readArgument(data, offset, additionalInformation);
      return [narrowInteger(value), next] as const;
    }),
    Match.when(1, () => {
      const [value, next] = readArgument(data, offset, additionalInformation);
      return [narrowInteger(-1n - value), next] as const;
    }),
    Match.whenOr(2, 3, () => {
      const [length, start] = readLength(data, offset, additionalInformation);
      if (data.byteLength < start + length) throw new CBORParseError("Insufficient bytes");
      const bytes = data.slice(start, start + length);
      if (majorType === 2) return [bytes, start + length] as const;
      const text = Result.getOrThrowWith(
        Result.try(() => utf8.decode(bytes)),
        () => new CBORParseError("Invalid UTF-8 text string"),
      );
      return [text, start + length] as const;
    }),
    Match.when(4, () => {
      const [count, start] = readLength(data, offset, additionalInformation);
      const elements: CBORValue[] = [];
      const end = Arr.reduce(indices(count), start, (cursor) => {
        const [element, next] = decodeItem(data, cursor, depth + 1);
        elements.push(element);
        return next;
      });
      return [elements, end] as const;
    }),
    Match.when(5, () => {
      const [count, start] = readLength(data, offset, additionalInformation);
      // A native `Map`: `CBORMap` is a public `ReadonlyMap`, and callers
      // recognise a decoded map with `instanceof Map`.
      const entries = new Map<string, CBORValue>();
      const end = Arr.reduce(indices(count), start, (cursor) => {
        const [key, afterKey] = decodeItem(data, cursor, depth + 1);
        const stringifiedKey = Predicate.isString(key)
          ? key
          : Predicate.isNumber(key) || Predicate.isBigInt(key)
            ? key.toString()
            : null;
        if (stringifiedKey === null) throw new CBORParseError("Unsupported map key type");
        if (entries.has(stringifiedKey)) throw new CBORParseError("Duplicate map key");
        const [value, afterValue] = decodeItem(data, afterKey, depth + 1);
        entries.set(stringifiedKey, value);
        return afterValue;
      });
      return [entries, end] as const;
    }),
    Match.when(6, () => {
      // Tagged value — the tag itself carries no meaning for WebAuthn, so the
      // tagged value is returned directly.
      const [, start] = readArgument(data, offset, additionalInformation);
      return decodeItem(data, start, depth + 1);
    }),
    Match.orElse(() => {
      if (additionalInformation === 20) return [false, offset + 1] as const;
      if (additionalInformation === 21) return [true, offset + 1] as const;
      if (additionalInformation === 22) return [null, offset + 1] as const;
      if (additionalInformation === 23) return [undefined, offset + 1] as const;
      throw new CBORParseError("Unsupported simple value, float, or break");
    }),
  );
};

/**
 * Decode a single CBOR data item, returning it with the number of bytes
 * consumed. Trailing bytes are permitted (attested credential data is followed
 * by optional extensions).
 */
export const decodeCBOR = (data: Uint8Array): readonly [CBORValue, number] => {
  const [value, next] = decodeItem(data, 0, 0);
  return [value, next];
};

/** Decode a single CBOR data item, rejecting any trailing bytes. */
export const decodeCBORNoLeftoverBytes = (data: Uint8Array): CBORValue => {
  const [value, size] = decodeCBOR(data);
  if (size !== data.byteLength) {
    throw new CBORParseError(`${data.byteLength - size} leftover bytes`);
  }
  return value;
};

// ---------------------------------------------------------------------------
// COSE public keys (RFC 8152)
// ---------------------------------------------------------------------------

/** COSE algorithm identifier for ECDSA w/ SHA-256 (P-256). */
export const coseAlgorithmES256 = -7;
/** COSE algorithm identifier for EdDSA (Ed25519). */
export const coseAlgorithmEdDSA = -8;
/** COSE algorithm identifier for RSASSA-PKCS1-v1_5 w/ SHA-256. */
export const coseAlgorithmRS256 = -257;

/** COSE key types (`kty`), as their registered integer values. */
const COSEKeyType = {
  OKP: 1,
  EC2: 2,
  RSA: 3,
  Symmetric: 4,
} as const;

/** An EC2 (elliptic curve) COSE public key. */
export interface COSEEC2PublicKey {
  readonly curve: number;
  readonly x: bigint;
  readonly y: bigint;
}

/** An RSA COSE public key. */
export interface COSERSAPublicKey {
  readonly n: bigint;
  readonly e: bigint;
}

/** An OKP (octet key pair) COSE public key. */
export interface COSEOKPPublicKey {
  readonly curve: number;
  readonly x: Uint8Array;
}

/**
 * A COSE_Key map, validated lazily: each accessor checks only the parameters
 * that key type requires and throws otherwise.
 */
export class COSEPublicKey {
  constructor(private readonly decoded: CBORMap) {}

  /** The `kty` parameter (label 1). */
  type(): number {
    const value = this.decoded.get("1");
    if (!Predicate.isNumber(value)) {
      throw new CodecError({ message: "Invalid or missing parameter 'kty'" });
    }
    if (value !== 1 && value !== 2 && value !== 3 && value !== 4 && value !== 5 && value !== 6) {
      throw new CodecError({ message: `Unknown 'kty' value '${value}'` });
    }
    return value;
  }

  /** Whether an `alg` parameter (label 3) is present and well-formed. */
  isAlgorithmDefined(): boolean {
    if (!this.decoded.has("3")) return false;
    if (!Predicate.isNumber(this.decoded.get("3"))) {
      throw new CodecError({ message: "Invalid parameter 'alg'" });
    }
    return true;
  }

  /** The `alg` parameter (label 3), e.g. {@link coseAlgorithmES256}. */
  algorithm(): number {
    const value = this.decoded.get("3");
    if (!Predicate.isNumber(value)) {
      throw new CodecError({ message: "Invalid or missing parameter 'alg'" });
    }
    return value;
  }

  /** Interpret the key as an EC2 (P-256) public key. */
  ec2(): COSEEC2PublicKey {
    if (this.type() !== COSEKeyType.EC2) {
      throw new CodecError({ message: "Expected an elliptic curve public key" });
    }
    const curve = this.decoded.get("-1");
    if (!Predicate.isNumber(curve)) {
      throw new CodecError({ message: "Invalid or missing parameter 'crv'" });
    }
    const xBytes = this.decoded.get("-2");
    if (!(xBytes instanceof Uint8Array) || xBytes.byteLength !== 32) {
      throw new CodecError({ message: "Invalid or missing parameter 'x'" });
    }
    const yBytes = this.decoded.get("-3");
    if (!(yBytes instanceof Uint8Array) || yBytes.byteLength !== 32) {
      throw new CodecError({ message: "Invalid or missing parameter 'y'" });
    }
    return { curve, x: bigIntFromBytes(xBytes), y: bigIntFromBytes(yBytes) };
  }

  /** Interpret the key as a 2048-bit RSA public key. */
  rsa(): COSERSAPublicKey {
    if (this.type() !== COSEKeyType.RSA) {
      throw new CodecError({ message: "Expected an RSA public key" });
    }
    const nBytes = this.decoded.get("-1");
    if (!(nBytes instanceof Uint8Array) || nBytes.byteLength !== 256) {
      throw new CodecError({ message: "Invalid or missing parameter 'n'" });
    }
    const eBytes = this.decoded.get("-2");
    if (!(eBytes instanceof Uint8Array) || eBytes.byteLength !== 3) {
      throw new CodecError({ message: "Invalid or missing parameter 'e'" });
    }
    return { n: bigIntFromBytes(nBytes), e: bigIntFromBytes(eBytes) };
  }

  /** Interpret the key as an OKP (Ed25519) public key. */
  okp(): COSEOKPPublicKey {
    if (this.type() !== COSEKeyType.OKP) {
      throw new CodecError({ message: "Expected an octet key pair public key" });
    }
    const curve = this.decoded.get("-1");
    if (!Predicate.isNumber(curve)) {
      throw new CodecError({ message: "Invalid or missing parameter 'curve'" });
    }
    const x = this.decoded.get("-2");
    if (!(x instanceof Uint8Array)) {
      throw new CodecError({ message: "Invalid or missing parameter 'x'" });
    }
    if (this.decoded.has("-4")) {
      throw new CodecError({ message: "Unexpected parameter 'd'" });
    }
    return { curve, x };
  }
}

/**
 * Decode a COSE_Key from the head of `data`, returning it with the number of
 * bytes consumed (attested credential data may be followed by extensions).
 */
export const decodeCOSEPublicKey = (data: Uint8Array): readonly [COSEPublicKey, number] => {
  const [decoded, size] = Result.getOrThrowWith(
    Result.try(() => decodeCBOR(data)),
    () => new CodecError({ message: "Failed to decode CBOR" }),
  );
  if (!(decoded instanceof Map)) {
    throw new CodecError({ message: "Invalid CBOR map" });
  }
  return [new COSEPublicKey(decoded), size];
};

// ---------------------------------------------------------------------------
// clientDataJSON
// ---------------------------------------------------------------------------

/** The `type` member of `clientDataJSON`. */
export const ClientDataType = {
  Get: 0,
  Create: 1,
} as const;

/** The `type` member of `clientDataJSON`, as a value. */
export type ClientDataType = (typeof ClientDataType)[keyof typeof ClientDataType];

/** The `status` member of `clientDataJSON.tokenBinding`. */
const TokenBindingStatus = {
  Supported: 0,
  Present: 1,
} as const;

/** The `status` member of `clientDataJSON.tokenBinding`, as a value. */
export type TokenBindingStatus = (typeof TokenBindingStatus)[keyof typeof TokenBindingStatus];

/** Token-binding information, when the client supplies it. */
export interface TokenBinding {
  readonly id: Uint8Array;
  readonly status: TokenBindingStatus;
}

/** A parsed and validated `clientDataJSON`. */
export interface ClientData {
  readonly type: ClientDataType;
  readonly challenge: Uint8Array;
  readonly origin: string;
  readonly crossOrigin: boolean;
  readonly tokenBinding: TokenBinding | null;
}

/** Thrown when `clientDataJSON` is missing required members or malformed. */
export class ClientDataParseError extends Error {
  constructor(message: string) {
    super(`Failed to parse client data: ${message}`);
    this.name = "ClientDataParseError";
  }
}

const BASE64URL_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

/**
 * Strict base64url decode, tolerating (but not requiring) `=` padding.
 * Throws on any character outside the base64url alphabet, so a malformed
 * challenge is rejected rather than silently truncated the way
 * `Buffer.from(s, "base64")` would.
 */
const decodeBase64urlIgnorePadding = (encoded: string): Uint8Array => {
  const body = encoded.replace(/=+$/u, "");
  if (encoded.length - body.length > 2) throw new CodecError({ message: "Invalid padding" });
  if (body.length % 4 === 1) throw new CodecError({ message: "Invalid length" });

  // Code points, as `for…of` iterated them; every valid one is a single unit.
  const sextets = Arr.map(Arr.fromIterable(body), (char) => {
    const index = BASE64URL_ALPHABET.indexOf(char);
    if (index < 0) throw new CodecError({ message: "Invalid character" });
    return index;
  });
  // Each character contributes 6 bits; every complete 8 bits is one byte.
  const bits = Arr.map(sextets, (sextet) => sextet.toString(2).padStart(6, "0")).join("");
  const octets = Arr.chunksOf(bits.split(""), 8);
  const remainder = bits.length % 8;
  // Any remaining bits must be zero padding.
  if (remainder > 0 && bits.slice(bits.length - remainder).includes("1")) {
    throw new CodecError({ message: "Invalid padding bits" });
  }
  return Uint8Array.from(
    Arr.map(
      Arr.filter(octets, (octet) => octet.length === 8),
      (octet) => parseInt(octet.join(""), 2),
    ),
  );
};

/** `JSON.parse`, as a schema: any JSON value. */
const decodeJsonOption = Schema.decodeUnknownOption(Schema.fromJsonString(Schema.Unknown));

/** Decode a base64url string property, throwing `message` when it is not one. */
const base64urlProperty = (value: object, key: string, message: string): Uint8Array => {
  const raw = Predicate.hasProperty(value, key) ? value[key] : undefined;
  if (!Predicate.isString(raw)) {
    throw new ClientDataParseError(message);
  }
  return Result.getOrThrowWith(
    Result.try(() => decodeBase64urlIgnorePadding(raw)),
    () => new ClientDataParseError(message),
  );
};

/** The ceremony `type` of the client data. */
const clientDataType = (parsed: object): ClientDataType => {
  const rawType = Predicate.hasProperty(parsed, "type") ? parsed.type : undefined;
  if (rawType === "webauthn.get") return ClientDataType.Get;
  if (rawType === "webauthn.create") return ClientDataType.Create;
  throw new ClientDataParseError("Missing or invalid property 'type'");
};

/** The optional `crossOrigin` flag, `false` when absent. */
const clientDataCrossOrigin = (parsed: object): boolean => {
  if (!Predicate.hasProperty(parsed, "crossOrigin")) return false;
  if (!Predicate.isBoolean(parsed.crossOrigin)) {
    throw new ClientDataParseError("Invalid property 'crossOrigin'");
  }
  return parsed.crossOrigin;
};

/** The `tokenBinding.status` value. */
const tokenBindingStatus = (raw: object): TokenBindingStatus => {
  const rawStatus = Predicate.hasProperty(raw, "status") ? raw.status : undefined;
  if (rawStatus === "present") return TokenBindingStatus.Present;
  if (rawStatus === "supported") return TokenBindingStatus.Supported;
  throw new ClientDataParseError("Missing or invalid property 'tokenBinding.status'");
};

/** The optional `tokenBinding` member, `null` when absent. */
const clientDataTokenBinding = (parsed: object): TokenBinding | null => {
  if (!Predicate.hasProperty(parsed, "tokenBinding")) return null;
  const raw = parsed.tokenBinding;
  // Any non-null object, arrays included.
  if (!Predicate.isObjectOrArray(raw)) {
    throw new ClientDataParseError("Invalid property 'tokenBinding'");
  }
  const id = base64urlProperty(raw, "id", "Missing or invalid property 'tokenBinding.id'");
  const status = tokenBindingStatus(raw);
  return { id, status };
};

/** Parse and validate the `clientDataJSON` a client returns. */
export function parseClientDataJSON(encoded: Uint8Array): ClientData {
  const parsed = Option.getOrThrowWith(
    decodeJsonOption(new TextDecoder().decode(encoded)),
    () => new ClientDataParseError("Invalid client data JSON"),
  );
  // Any non-null object, arrays included.
  if (!Predicate.isObjectOrArray(parsed)) {
    throw new ClientDataParseError("Invalid client data JSON");
  }

  const type = clientDataType(parsed);
  const challenge = base64urlProperty(
    parsed,
    "challenge",
    "Missing or invalid property 'challenge'",
  );

  const origin = Predicate.hasProperty(parsed, "origin") ? parsed.origin : undefined;
  if (!Predicate.isString(origin)) {
    throw new ClientDataParseError("Missing or invalid property 'origin'");
  }

  const crossOrigin = clientDataCrossOrigin(parsed);
  const tokenBinding = clientDataTokenBinding(parsed);

  return { type, challenge, origin, crossOrigin, tokenBinding };
}

// ---------------------------------------------------------------------------
// Authenticator data
// ---------------------------------------------------------------------------

/** Attested credential data, present only on registration responses. */
export interface AttestedCredential {
  readonly authenticatorAAGUID: Uint8Array;
  readonly id: Uint8Array;
  readonly publicKey: COSEPublicKey;
}

/** Thrown when authenticator data is truncated or otherwise malformed. */
export class AuthenticatorDataParseError extends Error {
  constructor(message: string) {
    super(`Failed to parse authenticator data: ${message}`);
    this.name = "AuthenticatorDataParseError";
  }
}

/** Parsed authenticator data (WebAuthn §6.1). */
export class AuthenticatorData {
  constructor(
    readonly relyingPartyIdHash: Uint8Array,
    readonly userPresent: boolean,
    readonly userVerified: boolean,
    readonly signatureCounter: number,
    readonly credential: AttestedCredential | null,
  ) {}

  /**
   * Constant-time check that this response was produced for `relyingPartyId`
   * (the authenticator reports SHA-256 of the RP ID, never the ID itself).
   */
  verifyRelyingPartyIdHash(relyingPartyId: string): boolean {
    return timingSafeEqualBytes(
      this.relyingPartyIdHash,
      sha256(new TextEncoder().encode(relyingPartyId)),
    );
  }
}

/** A big-endian view over `data`'s own bytes; reads past its end throw `RangeError`. */
const view = (data: Uint8Array): DataView =>
  new DataView(data.buffer, data.byteOffset, data.byteLength);

const bigEndianUint16 = (data: Uint8Array, offset: number): number => view(data).getUint16(offset);

const bigEndianUint32 = (data: Uint8Array, offset: number): number => view(data).getUint32(offset);

/** Parse the authenticator data blob returned by an authenticator. */
export function parseAuthenticatorData(encoded: Uint8Array): AuthenticatorData {
  if (encoded.byteLength < 37) {
    throw new AuthenticatorDataParseError("Insufficient bytes");
  }
  const relyingPartyIdHash = encoded.slice(0, 32);
  const flags = view(encoded).getUint8(32);
  const userPresent = (flags & 0x01) === 1;
  const userVerified = ((flags >> 2) & 0x01) === 1;
  const signatureCounter = bigEndianUint32(encoded, 33);
  const includesAttestedCredentialData = ((flags >> 6) & 0x01) === 1;

  let credential: AttestedCredential | null = null;
  if (includesAttestedCredentialData) {
    if (encoded.byteLength < 37 + 18) {
      throw new AuthenticatorDataParseError("Invalid credential data");
    }
    const authenticatorAAGUID = encoded.slice(37, 53);
    const credentialIdLength = bigEndianUint16(encoded, 53);
    if (encoded.byteLength < 37 + 18 + credentialIdLength) {
      throw new AuthenticatorDataParseError("Insufficient bytes");
    }
    const id = encoded.slice(55, 55 + credentialIdLength);
    const [publicKey] = Result.getOrThrowWith(
      Result.try(() => decodeCOSEPublicKey(encoded.slice(55 + credentialIdLength))),
      () => new AuthenticatorDataParseError("Failed to parse public key"),
    );
    credential = { authenticatorAAGUID, id, publicKey };
  }

  return new AuthenticatorData(
    relyingPartyIdHash,
    userPresent,
    userVerified,
    signatureCounter,
    credential,
  );
}

// ---------------------------------------------------------------------------
// Attestation object
// ---------------------------------------------------------------------------

/** Attestation statement formats defined by the WebAuthn registry. */
const AttestationStatementFormat = {
  Packed: 0,
  TPM: 1,
  AndroidKey: 2,
  AndroidSafetyNet: 3,
  FIDOU2F: 4,
  AppleAnonymous: 5,
  None: 6,
} as const;

/** Attestation statement format, as a value. */
export type AttestationStatementFormat =
  (typeof AttestationStatementFormat)[keyof typeof AttestationStatementFormat];

const ATTESTATION_FORMATS: Readonly<Record<string, AttestationStatementFormat>> = {
  packed: AttestationStatementFormat.Packed,
  tpm: AttestationStatementFormat.TPM,
  "android-key": AttestationStatementFormat.AndroidKey,
  "android-safetynet": AttestationStatementFormat.AndroidSafetyNet,
  "fido-u2f": AttestationStatementFormat.FIDOU2F,
  none: AttestationStatementFormat.None,
  apple: AttestationStatementFormat.AppleAnonymous,
};

/** A parsed attestation object (WebAuthn §6.5). */
export interface AttestationObject {
  readonly format: AttestationStatementFormat;
  readonly authenticatorData: AuthenticatorData;
  /**
   * The raw attestation statement map. effect-auth does not verify attestation
   * statements (the RP trusts the platform, per the `none`-attestation model),
   * so it is surfaced undecoded for callers that want it.
   */
  readonly attestationStatement: CBORMap;
}

/** Thrown when an attestation object is malformed or uses an unknown format. */
export class AttestationObjectParseError extends Error {
  constructor(message: string) {
    super(`Failed to parse attestation object: ${message}`);
    this.name = "AttestationObjectParseError";
  }
}

/** Parse the CBOR attestation object returned during registration. */
export function parseAttestationObject(encoded: Uint8Array): AttestationObject {
  const decoded = Result.getOrThrowWith(
    Result.try(() => decodeCBORNoLeftoverBytes(encoded)),
    () => new AttestationObjectParseError("Invalid CBOR data"),
  );
  if (!(decoded instanceof Map)) {
    throw new AttestationObjectParseError("Invalid CBOR data");
  }

  const fmt = decoded.get("fmt");
  if (!Predicate.isString(fmt)) {
    throw new AttestationObjectParseError("Invalid or missing property 'fmt'");
  }
  const attStmt = decoded.get("attStmt");
  if (!(attStmt instanceof Map)) {
    throw new AttestationObjectParseError("Invalid or missing property 'attStmt'");
  }
  const authData = decoded.get("authData");
  if (!(authData instanceof Uint8Array)) {
    throw new AttestationObjectParseError("Invalid or missing property 'authData'");
  }

  const format = ATTESTATION_FORMATS[fmt];
  if (format === undefined) {
    throw new AttestationObjectParseError(`Unsupported attestation statement format '${fmt}'`);
  }

  return {
    format,
    authenticatorData: parseAuthenticatorData(authData),
    attestationStatement: attStmt,
  };
}
