import {
  Array as Arr,
  Clock,
  Crypto,
  Data,
  Effect,
  Option,
  Predicate,
  String as Str,
} from "effect";
import * as Cipher from "../Cipher.ts";
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

/**
 * Split a string of `0`/`1` digits into consecutive groups of `size` bits; the
 * last group is shorter when `bits.length` is not a multiple of `size`.
 */
const bitGroups = (bits: string, size: number): ReadonlyArray<string> =>
  Arr.map(Arr.chunksOf(bits.split(""), size), (group) => group.join(""));

/**
 * Generate cryptographically secure random bytes for OTP secret
 * @param length - Number of bytes to generate (default: 20)
 * @returns Effect that produces random bytes
 */
export const generateSecret = (
  crypto: Crypto.Crypto,
  length: number = 20,
): Effect.Effect<Buffer, Errors.HashingError> =>
  Effect.gen(function* () {
    if (!Number.isInteger(length) || length < 16) {
      return yield* new Errors.HashingError({
        message: "Invalid secret length: must be a positive integer of at least 16 bytes",
      });
    }
    const bytes = yield* crypto
      .randomBytes(length)
      .pipe(
        Effect.mapError(
          (cause) =>
            new Errors.HashingError({ message: "Failed to generate random secret", cause }),
        ),
      );
    return Buffer.from(bytes);
  });

/**
 * Encode bytes to base32 (RFC 4648)
 * Used for encoding OTP secrets
 */
export const encodeBase32 = (buffer: Buffer): string => {
  // Each byte contributes 8 bits; every 5 bits is one character, and a final
  // partial group is right-padded with zero bits.
  const bits = Arr.map(Arr.fromIterable(buffer), (byte) => byte.toString(2).padStart(8, "0")).join(
    "",
  );
  return Arr.map(bitGroups(bits, 5), (group) =>
    base32Alphabet.charAt(parseInt(group.padEnd(5, "0"), 2)),
  ).join("");
};

/**
 * Decode base32 string to bytes (RFC 4648)
 */
export const decodeBase32 = (base32: string): Effect.Effect<Buffer, Errors.HashingError> =>
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
        onNone: () => {
          // Each character contributes 5 bits; every complete 8 bits is one
          // byte, and trailing bits short of a byte are dropped.
          const bits = Arr.map(chars, (char) =>
            base32Alphabet.indexOf(char).toString(2).padStart(5, "0"),
          ).join("");
          const bytes = Arr.map(
            Arr.filter(bitGroups(bits, 8), (group) => group.length === 8),
            (group) => parseInt(group, 2),
          );
          return Effect.succeed(Buffer.from(bytes));
        },
      },
    );
  });

/**
 * Generate HMAC-based One-Time Password (HOTP)
 * Following RFC 4226
 *
 * @param secret - Base32-encoded secret or raw Buffer
 * @param counter - Counter value
 * @param config - HOTP configuration
 * @returns Effect that produces the OTP string
 */
export const generateHotp = (
  secret: string | Buffer,
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
    if (Predicate.isString(secret)) {
      const trimmed = secret.trim();
      if (Str.isEmpty(trimmed)) {
        return yield* new Errors.HashingError({
          message: "Secret must be a non-empty string",
        });
      }
    }

    // Decode secret if it's a string
    const secretBuffer = Predicate.isString(secret) ? yield* decodeBase32(secret) : secret;

    // Validate buffer is not empty
    if (secretBuffer.byteLength === 0) {
      return yield* new Errors.HashingError({
        message: "Secret buffer cannot be empty",
      });
    }

    // Create counter buffer (8 bytes, big-endian)
    const counterBuffer = Buffer.alloc(8);
    counterBuffer.writeBigUInt64BE(BigInt(counter), 0);

    // Generate HMAC
    const hash = Cipher.hmac(algorithm, secretBuffer, counterBuffer);

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
 * @param secret - Base32-encoded secret or raw Buffer
 * @param counter - Counter value
 * @param config - HOTP configuration
 * @returns Effect that produces true if valid, false otherwise
 */
export const verifyHotp = (
  token: string,
  secret: string | Buffer,
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

    return timingSafeEqualBytes(Buffer.from(token), Buffer.from(expectedToken));
  });

/**
 * Generate Time-based One-Time Password (TOTP)
 * Following RFC 6238
 *
 * @param secret - Base32-encoded secret or raw Buffer
 * @param config - TOTP configuration
 * @returns Effect that produces the OTP string
 */
export const generateTotp = (
  secret: string | Buffer,
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
 * @param secret - Base32-encoded secret or raw Buffer
 * @param config - TOTP configuration
 * @returns Effect that produces the matched time-step counter, or `null` if
 *   the token is invalid. Callers should persist the counter and reject
 *   subsequent submissions with the same or lower counter to prevent replay.
 */
export const verifyTotp = (
  token: string,
  secret: string | Buffer,
  config: TotpConfig = {},
): Effect.Effect<number | null, Errors.HashingError> =>
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
              timingSafeEqualBytes(Buffer.from(token), Buffer.from(expectedToken)),
          ),
        ),
    );

    return Option.getOrNull(matched);
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
  if (!Predicate.isString(secret)) {
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
  crypto: Crypto.Crypto,
  length: number = 20,
): Effect.Effect<string, Errors.HashingError> =>
  Effect.gen(function* () {
    const bytes = yield* generateSecret(crypto, length);
    return encodeBase32(bytes);
  });
