import { Clock, Data, Effect } from "effect";
import * as Arr from "effect/Array";
import * as Option from "effect/Option";
import * as P from "effect/Predicate";
import * as Str from "effect/String";
import { SecureRandom } from "effect/crypto";
import * as Cipher from "../Cipher.ts";
import * as PlatformCrypto from "../PlatformCrypto.ts";
import * as Errors from "../Errors.ts";
import { timingSafeEqualBytes } from "../TokenHash.ts";

/**
 * OTP (One-Time Password) utilities for HOTP and TOTP
 * Following RFC 4226 (HOTP) and RFC 6238 (TOTP) standards
 * Inspired by Oslo's OTP implementation patterns
 */

/**
 * Configuration for TOTP generation
 */
export interface TotpConfig {
  /** Time step in seconds (default: 30) */
  readonly period?: number;
  /** Number of digits in the OTP (default: 6) */
  readonly digits?: number;
  /** HMAC algorithm to use (default: "sha1") */
  readonly algorithm?: "sha1" | "sha256" | "sha512";
  /** Number of periods to check before and after current time (default: 1) */
  readonly window?: number;
}

/**
 * Configuration for HOTP generation
 */
export interface HotpConfig {
  /** Number of digits in the OTP (default: 6) */
  readonly digits?: number;
  /** HMAC algorithm to use (default: "sha1") */
  readonly algorithm?: "sha1" | "sha256" | "sha512";
}

/**
 * OTP URI parameters for generating QR codes
 */
export interface OtpUriParams {
  /** Type of OTP: totp or hotp */
  readonly type: "totp" | "hotp";
  /** Label (typically username or email) */
  readonly label: string;
  /** Issuer name (e.g., your app name) */
  readonly issuer: string;
  /** Base32-encoded secret */
  readonly secret: string;
  /** HOTP counter (required for hotp) */
  readonly counter?: number;
  /** TOTP period in seconds (optional, default: 30) */
  readonly period?: number;
  /** Number of digits (optional, default: 6) */
  readonly digits?: number;
  /** Algorithm (optional, default: "sha1") */
  readonly algorithm?: "sha1" | "sha256" | "sha512";
}

/** A character outside the RFC 4648 base32 alphabet; the `cause` of a failed {@link decodeBase32}. */
class InvalidBase32CharacterError extends Data.TaggedError("InvalidBase32CharacterError")<{
  readonly message: string;
}> {}

/** An {@link OtpUriParams} that {@link generateOtpUri} cannot encode. */
class OtpUriError extends Data.TaggedError("OtpUriError")<{
  readonly message: string;
}> {}

const base32Alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

/** `f` of `0` to `n - 1`; `Arr.makeBy` makes at least one. */
const times = <A>(n: number, f: (i: number) => A): Array<A> => (n > 0 ? Arr.makeBy(n, f) : []);

/** Consecutive groups of `size` (the last may be shorter), in linear time, unlike `Arr.chunksOf`. */
const groupsOf = <A>(items: ReadonlyArray<A>, size: number): Array<ReadonlyArray<A>> =>
  times(Math.ceil(items.length / size), (i) => items.slice(i * size, (i + 1) * size));

/**
 * Generate cryptographically secure random bytes for OTP secret
 * @param length - Number of bytes to generate (default: 20)
 * @returns Effect that produces random bytes
 */
export const generateSecret = (
  crypto: typeof SecureRandom.SecureRandom.Service,
  length: number = 20,
): Effect.Effect<Uint8Array, Errors.HashingError> =>
  Effect.gen(function* () {
    if (!Number.isInteger(length) || length < 16) {
      return yield* new Errors.HashingError({
        message: "Invalid secret length: must be a positive integer of at least 16 bytes",
      });
    }
    const bytes = yield* crypto.randomBytes(length);
    return bytes;
  });

/** The UTF-8 bytes of a string, for the timing-safe code comparisons. */
const utf8 = (text: string): Uint8Array => new TextEncoder().encode(text);

/**
 * Encode bytes to base32 (RFC 4648)
 * Used for encoding OTP secrets
 */
export const encodeBase32 = (buffer: Uint8Array): string =>
  // Each 5 bytes are 40 bits, 8 characters: arithmetic on one number per
  // group, so the work stays linear with no per-bit strings. A final partial
  // group is right-padded with zero bits.
  Arr.flatMap(groupsOf(Arr.fromIterable(buffer), 5), (group) => {
    const value = Arr.reduce(group, 0, (acc, byte) => acc * 256 + byte) * 256 ** (5 - group.length);
    return times(Math.ceil((group.length * 8) / 5), (i) =>
      base32Alphabet.charAt(Math.floor(value / 2 ** (35 - 5 * i)) % 32),
    );
  }).join("");

/**
 * Decode base32 string to bytes (RFC 4648)
 */
export const decodeBase32 = (base32: string): Effect.Effect<Uint8Array, Errors.HashingError> =>
  Effect.suspend(() => {
    // UTF-16 code units, so an invalid character is reported as it was indexed.
    const chars = base32.toUpperCase().replace(/[=\s]/g, "").split("");
    return Option.match(
      Arr.findFirst(chars, (char) => base32Alphabet.indexOf(char) === -1),
      {
        onSome: (char) =>
          Effect.fail(
            new Errors.HashingError({
              message: "Failed to decode base32 string",
              cause: new InvalidBase32CharacterError({
                message: `Invalid base32 character: ${char}`,
              }),
            }),
          ),
        onNone: () =>
          // Each 8 characters are 40 bits, 5 bytes, as in `encodeBase32`;
          // trailing bits short of a byte are dropped.
          Effect.succeed(
            Uint8Array.from(
              Arr.flatMap(groupsOf(chars, 8), (group) => {
                const value =
                  Arr.reduce(group, 0, (acc, char) => acc * 32 + base32Alphabet.indexOf(char)) *
                  32 ** (8 - group.length);
                return times(
                  Math.floor((group.length * 5) / 8),
                  (i) => Math.floor(value / 2 ** (32 - 8 * i)) % 256,
                );
              }),
            ),
          ),
      },
    );
  });

/**
 * Generate HMAC-based One-Time Password (HOTP)
 * Following RFC 4226
 *
 * @param secret - Base32-encoded secret or raw bytes
 * @param counter - Counter value
 * @param config - HOTP configuration
 * @returns Effect that produces the OTP string
 */
export const generateHotp = (
  secret: string | Uint8Array,
  counter: number,
  config: HotpConfig = {},
): Effect.Effect<string, Errors.HashingError> =>
  Effect.gen(function* () {
    // Validate counter
    if (!Number.isInteger(counter) || counter < 0) {
      return yield* new Errors.HashingError({
        message: "Counter must be a non-negative integer",
      });
    }

    // Validate digits
    const digits = config?.digits ?? 6;
    if (!Number.isInteger(digits) || digits < 6 || digits > 8) {
      return yield* new Errors.HashingError({
        message: "Invalid digits parameter for HOTP. It must be an integer between 6 and 8.",
      });
    }

    const algorithm = config?.algorithm ?? "sha1";

    // Validate and decode secret if it's a string
    if (P.isString(secret)) {
      const trimmed = secret.trim();
      if (Str.isEmpty(trimmed)) {
        return yield* new Errors.HashingError({
          message: "Secret must be a non-empty string",
        });
      }
    }

    // Decode secret if it's a string
    const secretBuffer = P.isString(secret) ? yield* decodeBase32(secret) : secret;

    // Validate buffer is not empty
    if (secretBuffer.byteLength === 0) {
      return yield* new Errors.HashingError({
        message: "Secret buffer cannot be empty",
      });
    }

    // Create counter buffer (8 bytes, big-endian)
    const counterBuffer = new Uint8Array(8);
    new DataView(counterBuffer.buffer).setBigUint64(0, BigInt(counter));

    // Generate HMAC
    const hash = yield* Cipher.hmac(algorithm, secretBuffer, counterBuffer).pipe(
      PlatformCrypto.provide,
      Effect.mapError((cause) => new Errors.HashingError({ message: cause.message, cause })),
    );

    // Dynamic truncation (RFC 4226 Section 5.3)
    const offset = hash[hash.length - 1] & 0x0f;
    const binary =
      ((hash[offset] & 0x7f) << 24) |
      ((hash[offset + 1] & 0xff) << 16) |
      ((hash[offset + 2] & 0xff) << 8) |
      (hash[offset + 3] & 0xff);

    // Generate OTP
    const otp = binary % Math.pow(10, digits);
    return otp.toString().padStart(digits, "0");
  });

/**
 * Verify HMAC-based One-Time Password (HOTP)
 *
 * @param token - The OTP token to verify
 * @param secret - Base32-encoded secret or raw bytes
 * @param counter - Counter value
 * @param config - HOTP configuration
 * @returns Effect that produces true if valid, false otherwise
 */
export const verifyHotp = (
  token: string,
  secret: string | Uint8Array,
  counter: number,
  config: HotpConfig = {},
): Effect.Effect<boolean, Errors.HashingError> =>
  Effect.gen(function* () {
    // Validate token: must be a non-empty string of digits
    if (!token || Str.isEmpty(token) || !/^\d+$/u.test(token)) {
      return false;
    }

    const expectedToken = yield* generateHotp(secret, counter, config);

    // Timing-safe comparison
    if (token.length !== expectedToken.length) {
      return false;
    }

    return timingSafeEqualBytes(utf8(token), utf8(expectedToken));
  });

/**
 * Generate Time-based One-Time Password (TOTP)
 * Following RFC 6238
 *
 * @param secret - Base32-encoded secret or raw bytes
 * @param config - TOTP configuration
 * @returns Effect that produces the OTP string
 */
export const generateTotp = (
  secret: string | Uint8Array,
  config: TotpConfig = {},
): Effect.Effect<string, Errors.HashingError> =>
  Effect.flatMap(Clock.currentTimeMillis, (millis) => {
    const period = config?.period ?? 30;
    const currentTime = Math.floor(millis / 1000);
    const counter = Math.floor(currentTime / period);
    const hotpConfig: HotpConfig = {
      ...(config?.digits !== undefined && { digits: config.digits }),
      ...(config?.algorithm !== undefined && { algorithm: config.algorithm }),
    };

    return generateHotp(secret, counter, hotpConfig);
  });

/**
 * Verify Time-based One-Time Password (TOTP).
 * Checks the current time step and adjacent steps within the window.
 *
 * @param token - The OTP token to verify
 * @param secret - Base32-encoded secret or raw bytes
 * @param config - TOTP configuration
 * @returns Effect that produces the matched time-step counter, or `None` if
 *   the token is invalid. Callers should persist the counter and reject
 *   subsequent submissions with the same or lower counter to prevent replay.
 */
export const verifyTotp = (
  token: string,
  secret: string | Uint8Array,
  config: TotpConfig = {},
): Effect.Effect<Option.Option<number>, Errors.HashingError> =>
  Effect.gen(function* () {
    // Validate and normalize period
    let period = config?.period ?? 30;
    if (!Number.isFinite(period) || period <= 0) {
      period = 30;
    } else {
      period = Math.floor(period);
    }

    // Validate and normalize window
    let window = config?.window ?? 1;
    if (!Number.isFinite(window) || window < 0) {
      window = 1;
    } else {
      window = Math.floor(window);
    }

    const currentTime = Math.floor((yield* Clock.currentTimeMillis) / 1000);
    const currentCounter = Math.floor(currentTime / period);

    const hotpConfig: HotpConfig = {
      ...(config?.digits !== undefined && { digits: config.digits }),
      ...(config?.algorithm !== undefined && { algorithm: config.algorithm }),
    };

    // Check current time step and adjacent steps within window, in order,
    // stopping at the first match
    const matched = yield* Effect.findFirst(
      Arr.range(currentCounter - window, currentCounter + window),
      (counter) =>
        generateHotp(secret, counter, hotpConfig).pipe(
          // Timing-safe comparison
          Effect.map(
            (expectedToken) =>
              token.length === expectedToken.length &&
              timingSafeEqualBytes(utf8(token), utf8(expectedToken)),
          ),
        ),
    );

    return matched;
  });

/**
 * Generate an OTP URI for QR code generation
 * Compatible with Google Authenticator and other OTP apps
 *
 * @param params - OTP URI parameters
 * @returns The otpauth:// URI string
 */
export const generateOtpUri = (params: OtpUriParams): string => {
  const { type, label, issuer, secret, counter, period, digits, algorithm } = params;

  // Validate secret is a valid base32 string
  if (!P.isString(secret)) {
    throw new OtpUriError({ message: "Secret must be a string" });
  }
  const trimmed = secret.trim();
  if (Str.isEmpty(trimmed)) {
    throw new OtpUriError({ message: "Secret cannot be empty" });
  }
  // Allow only Base32 characters A-Z and 2-7 (case-insensitive), with optional padding
  if (!/^[A-Z2-7]+=*$/i.test(trimmed)) {
    throw new OtpUriError({ message: "Invalid Base32 secret provided to generateOtpUri" });
  }

  // Normalize secret for URI (trim, uppercase, and remove padding)
  const normalizedSecret = trimmed.toUpperCase().replace(/=+$/, "");

  // Validate that counter is provided for HOTP
  if (type === "hotp" && counter === undefined) {
    throw new OtpUriError({ message: "Counter parameter is required for HOTP URIs" });
  }

  // Encode label and issuer for URI
  const encodedLabel = encodeURIComponent(label);
  const encodedIssuer = encodeURIComponent(issuer);

  // Build URI
  let uri = `otpauth://${type}/${encodedIssuer}:${encodedLabel}?secret=${normalizedSecret}&issuer=${encodedIssuer}`;

  // Add optional parameters
  if (type === "hotp" && counter !== undefined) {
    uri += `&counter=${counter}`;
  }
  if (type === "totp" && period !== undefined && period !== 30) {
    uri += `&period=${period}`;
  }
  if (digits !== undefined && digits !== 6) {
    uri += `&digits=${digits}`;
  }
  if (algorithm !== undefined && algorithm !== "sha1") {
    uri += `&algorithm=${algorithm.toUpperCase()}`;
  }

  return uri;
};

/**
 * Generate a random OTP secret and return it as a base32 string
 *
 * @param length - Number of bytes to generate (default: 20)
 * @returns Effect that produces a base32-encoded secret
 */
export const generateBase32Secret = (
  crypto: typeof SecureRandom.SecureRandom.Service,
  length: number = 20,
): Effect.Effect<string, Errors.HashingError> =>
  Effect.gen(function* () {
    const bytes = yield* generateSecret(crypto, length);
    return encodeBase32(bytes);
  });
