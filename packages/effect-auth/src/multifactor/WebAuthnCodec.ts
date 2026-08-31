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
  let value = 0n;
  for (let i = 0; i < size; i++) {
    value = (value << 8n) | BigInt(data[offset + 1 + i]!);
  }
  return [value, offset + 1 + size];
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
  if (data.byteLength < offset + 1) throw new CBORParseError("Insufficient bytes");

  const head = data[offset]!;
  const majorType = head >> 5;
  const additionalInformation = head & 0x1f;

  switch (majorType) {
    case 0: {
      const [value, next] = readArgument(data, offset, additionalInformation);
      return [narrowInteger(value), next];
    }
    case 1: {
      const [value, next] = readArgument(data, offset, additionalInformation);
      return [narrowInteger(-1n - value), next];
    }
    case 2:
    case 3: {
      const [length, start] = readLength(data, offset, additionalInformation);
      if (data.byteLength < start + length) throw new CBORParseError("Insufficient bytes");
      const bytes = data.slice(start, start + length);
      if (majorType === 2) return [bytes, start + length];
      try {
        return [utf8.decode(bytes), start + length];
      } catch {
        throw new CBORParseError("Invalid UTF-8 text string");
      }
    }
    case 4: {
      const [count, start] = readLength(data, offset, additionalInformation);
      const elements: CBORValue[] = [];
      let cursor = start;
      for (let i = 0; i < count; i++) {
        const [element, next] = decodeItem(data, cursor, depth + 1);
        elements.push(element);
        cursor = next;
      }
      return [elements, cursor];
    }
    case 5: {
      const [count, start] = readLength(data, offset, additionalInformation);
      const entries = new Map<string, CBORValue>();
      let cursor = start;
      for (let i = 0; i < count; i++) {
        const [key, afterKey] = decodeItem(data, cursor, depth + 1);
        const stringifiedKey =
          typeof key === "string"
            ? key
            : typeof key === "number" || typeof key === "bigint"
              ? key.toString()
              : null;
        if (stringifiedKey === null) throw new CBORParseError("Unsupported map key type");
        if (entries.has(stringifiedKey)) throw new CBORParseError("Duplicate map key");
        const [value, afterValue] = decodeItem(data, afterKey, depth + 1);
        entries.set(stringifiedKey, value);
        cursor = afterValue;
      }
      return [entries, cursor];
    }
    case 6: {
      // Tagged value — the tag itself carries no meaning for WebAuthn, so the
      // tagged value is returned directly.
      const [, start] = readArgument(data, offset, additionalInformation);
      return decodeItem(data, start, depth + 1);
    }
    default: {
      if (additionalInformation === 20) return [false, offset + 1];
      if (additionalInformation === 21) return [true, offset + 1];
      if (additionalInformation === 22) return [null, offset + 1];
      if (additionalInformation === 23) return [undefined, offset + 1];
      throw new CBORParseError("Unsupported simple value, float, or break");
    }
  }
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
/** COSE elliptic-curve identifier for P-256. */
export const coseEllipticCurveP256 = 1;
/** COSE elliptic-curve identifier for Ed25519. */
export const coseEllipticCurveEd25519 = 6;

/** COSE key types (`kty`), as their registered integer values. */
export const COSEKeyType = {
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

/** Big-endian unsigned integer from bytes. */
const bigIntFromBytes = (bytes: Uint8Array): bigint => {
  let value = 0n;
  for (const byte of bytes) value = (value << 8n) | BigInt(byte);
  return value;
};

/**
 * A COSE_Key map, validated lazily: each accessor checks only the parameters
 * that key type requires and throws otherwise.
 */
export class COSEPublicKey {
  constructor(private readonly decoded: CBORMap) {}

  /** The `kty` parameter (label 1). */
  type(): number {
    const value = this.decoded.get("1");
    if (typeof value !== "number") {
      throw new Error("Invalid or missing parameter 'kty'");
    }
    if (value !== 1 && value !== 2 && value !== 3 && value !== 4 && value !== 5 && value !== 6) {
      throw new Error(`Unknown 'kty' value '${value}'`);
    }
    return value;
  }

  /** Whether an `alg` parameter (label 3) is present and well-formed. */
  isAlgorithmDefined(): boolean {
    if (!this.decoded.has("3")) return false;
    if (typeof this.decoded.get("3") !== "number") {
      throw new Error("Invalid parameter 'alg'");
    }
    return true;
  }

  /** The `alg` parameter (label 3), e.g. {@link coseAlgorithmES256}. */
  algorithm(): number {
    const value = this.decoded.get("3");
    if (typeof value !== "number") {
      throw new Error("Invalid or missing parameter 'alg'");
    }
    return value;
  }

  /** Interpret the key as an EC2 (P-256) public key. */
  ec2(): COSEEC2PublicKey {
    if (this.type() !== COSEKeyType.EC2) {
      throw new Error("Expected an elliptic curve public key");
    }
    const curve = this.decoded.get("-1");
    if (typeof curve !== "number") {
      throw new Error("Invalid or missing parameter 'crv'");
    }
    const xBytes = this.decoded.get("-2");
    if (!(xBytes instanceof Uint8Array) || xBytes.byteLength !== 32) {
      throw new Error("Invalid or missing parameter 'x'");
    }
    const yBytes = this.decoded.get("-3");
    if (!(yBytes instanceof Uint8Array) || yBytes.byteLength !== 32) {
      throw new Error("Invalid or missing parameter 'y'");
    }
    return { curve, x: bigIntFromBytes(xBytes), y: bigIntFromBytes(yBytes) };
  }

  /** Interpret the key as a 2048-bit RSA public key. */
  rsa(): COSERSAPublicKey {
    if (this.type() !== COSEKeyType.RSA) {
      throw new Error("Expected an RSA public key");
    }
    const nBytes = this.decoded.get("-1");
    if (!(nBytes instanceof Uint8Array) || nBytes.byteLength !== 256) {
      throw new Error("Invalid or missing parameter 'n'");
    }
    const eBytes = this.decoded.get("-2");
    if (!(eBytes instanceof Uint8Array) || eBytes.byteLength !== 3) {
      throw new Error("Invalid or missing parameter 'e'");
    }
    return { n: bigIntFromBytes(nBytes), e: bigIntFromBytes(eBytes) };
  }

  /** Interpret the key as an OKP (Ed25519) public key. */
  okp(): COSEOKPPublicKey {
    if (this.type() !== COSEKeyType.OKP) {
      throw new Error("Expected an octet key pair public key");
    }
    const curve = this.decoded.get("-1");
    if (typeof curve !== "number") {
      throw new Error("Invalid or missing parameter 'curve'");
    }
    const x = this.decoded.get("-2");
    if (!(x instanceof Uint8Array)) {
      throw new Error("Invalid or missing parameter 'x'");
    }
    if (this.decoded.has("-4")) {
      throw new Error("Unexpected parameter 'd'");
    }
    return { curve, x };
  }
}

/**
 * Decode a COSE_Key from the head of `data`, returning it with the number of
 * bytes consumed (attested credential data may be followed by extensions).
 */
export const decodeCOSEPublicKey = (data: Uint8Array): readonly [COSEPublicKey, number] => {
  let decoded: CBORValue;
  let size: number;
  try {
    [decoded, size] = decodeCBOR(data);
  } catch {
    throw new Error("Failed to decode CBOR");
  }
  if (!(decoded instanceof Map)) {
    throw new Error("Invalid CBOR map");
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
export const TokenBindingStatus = {
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
  let end = encoded.length;
  while (end > 0 && encoded[end - 1] === "=") end--;
  if (encoded.length - end > 2) throw new Error("Invalid padding");
  const body = encoded.slice(0, end);
  if (body.length % 4 === 1) throw new Error("Invalid length");

  const out = new Uint8Array(Math.floor((body.length * 3) / 4));
  let outIndex = 0;
  let buffer = 0;
  let bits = 0;
  for (const char of body) {
    const index = BASE64URL_ALPHABET.indexOf(char);
    if (index < 0) throw new Error("Invalid character");
    buffer = (buffer << 6) | index;
    bits += 6;
    if (bits >= 8) {
      bits -= 8;
      out[outIndex++] = (buffer >> bits) & 0xff;
    }
  }
  // Any remaining bits must be zero padding.
  if (bits > 0 && (buffer & ((1 << bits) - 1)) !== 0) throw new Error("Invalid padding bits");
  return out.subarray(0, outIndex);
};

/** Parse and validate the `clientDataJSON` a client returns. */
export function parseClientDataJSON(encoded: Uint8Array): ClientData {
  let parsed: unknown;
  try {
    parsed = JSON.parse(new TextDecoder().decode(encoded));
  } catch {
    throw new ClientDataParseError("Invalid client data JSON");
  }
  if (parsed === null || typeof parsed !== "object") {
    throw new ClientDataParseError("Invalid client data JSON");
  }
  const record = parsed as Record<string, unknown>;

  let type: ClientDataType;
  if (record["type"] === "webauthn.get") {
    type = ClientDataType.Get;
  } else if (record["type"] === "webauthn.create") {
    type = ClientDataType.Create;
  } else {
    throw new ClientDataParseError("Missing or invalid property 'type'");
  }

  if (typeof record["challenge"] !== "string") {
    throw new ClientDataParseError("Missing or invalid property 'challenge'");
  }
  let challenge: Uint8Array;
  try {
    challenge = decodeBase64urlIgnorePadding(record["challenge"]);
  } catch {
    throw new ClientDataParseError("Missing or invalid property 'challenge'");
  }

  const origin = record["origin"];
  if (typeof origin !== "string") {
    throw new ClientDataParseError("Missing or invalid property 'origin'");
  }

  let crossOrigin = false;
  if ("crossOrigin" in record) {
    if (typeof record["crossOrigin"] !== "boolean") {
      throw new ClientDataParseError("Invalid property 'crossOrigin'");
    }
    crossOrigin = record["crossOrigin"];
  }

  let tokenBinding: TokenBinding | null = null;
  if ("tokenBinding" in record) {
    const raw = record["tokenBinding"];
    if (raw === null || typeof raw !== "object") {
      throw new ClientDataParseError("Invalid property 'tokenBinding'");
    }
    const rawBinding = raw as Record<string, unknown>;
    if (typeof rawBinding["id"] !== "string") {
      throw new ClientDataParseError("Missing or invalid property 'tokenBinding.id'");
    }
    let id: Uint8Array;
    try {
      id = decodeBase64urlIgnorePadding(rawBinding["id"]);
    } catch {
      throw new ClientDataParseError("Missing or invalid property 'tokenBinding.id'");
    }
    let status: TokenBindingStatus;
    if (rawBinding["status"] === "present") {
      status = TokenBindingStatus.Present;
    } else if (rawBinding["status"] === "supported") {
      status = TokenBindingStatus.Supported;
    } else {
      throw new ClientDataParseError("Missing or invalid property 'tokenBinding.status'");
    }
    tokenBinding = { id, status };
  }

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

const bigEndianUint16 = (data: Uint8Array, offset: number): number =>
  (data[offset]! << 8) | data[offset + 1]!;

const bigEndianUint32 = (data: Uint8Array, offset: number): number =>
  data[offset]! * 0x1000000 +
  ((data[offset + 1]! << 16) | (data[offset + 2]! << 8) | data[offset + 3]!);

/** Parse the authenticator data blob returned by an authenticator. */
export function parseAuthenticatorData(encoded: Uint8Array): AuthenticatorData {
  if (encoded.byteLength < 37) {
    throw new AuthenticatorDataParseError("Insufficient bytes");
  }
  const relyingPartyIdHash = encoded.slice(0, 32);
  const flags = encoded[32]!;
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
    let publicKey: COSEPublicKey;
    try {
      [publicKey] = decodeCOSEPublicKey(encoded.slice(55 + credentialIdLength));
    } catch {
      throw new AuthenticatorDataParseError("Failed to parse public key");
    }
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
export const AttestationStatementFormat = {
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
  let decoded: CBORValue;
  try {
    decoded = decodeCBORNoLeftoverBytes(encoded);
  } catch {
    throw new AttestationObjectParseError("Invalid CBOR data");
  }
  if (!(decoded instanceof Map)) {
    throw new AttestationObjectParseError("Invalid CBOR data");
  }

  const fmt = decoded.get("fmt");
  if (typeof fmt !== "string") {
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
