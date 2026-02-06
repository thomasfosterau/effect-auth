import { Effect } from "effect"
import * as crypto from "node:crypto"
import * as Errors from "./errors.js"

/**
 * OTP (One-Time Password) utilities for HOTP and TOTP
 * Following RFC 4226 (HOTP) and RFC 6238 (TOTP) standards
 * Inspired by Oslo's OTP implementation patterns
 */

/**
 * Configuration for TOTP generation
 */
export interface TOTPConfig {
  /** Time step in seconds (default: 30) */
  readonly period?: number
  /** Number of digits in the OTP (default: 6) */
  readonly digits?: number
  /** HMAC algorithm to use (default: "sha1") */
  readonly algorithm?: "sha1" | "sha256" | "sha512"
  /** Number of periods to check before and after current time (default: 1) */
  readonly window?: number
}

/**
 * Configuration for HOTP generation
 */
export interface HOTPConfig {
  /** Number of digits in the OTP (default: 6) */
  readonly digits?: number
  /** HMAC algorithm to use (default: "sha1") */
  readonly algorithm?: "sha1" | "sha256" | "sha512"
}

/**
 * OTP URI parameters for generating QR codes
 */
export interface OTPURIParams {
  /** Type of OTP: totp or hotp */
  readonly type: "totp" | "hotp"
  /** Label (typically username or email) */
  readonly label: string
  /** Issuer name (e.g., your app name) */
  readonly issuer: string
  /** Base32-encoded secret */
  readonly secret: string
  /** HOTP counter (required for hotp) */
  readonly counter?: number
  /** TOTP period in seconds (optional, default: 30) */
  readonly period?: number
  /** Number of digits (optional, default: 6) */
  readonly digits?: number
  /** Algorithm (optional, default: "sha1") */
  readonly algorithm?: "sha1" | "sha256" | "sha512"
}

/**
 * Generate cryptographically secure random bytes for OTP secret
 * @param length - Number of bytes to generate (default: 20)
 * @returns Effect that produces random bytes
 */
export const generateSecret = (length: number = 20): Effect.Effect<Buffer, Errors.HashingError> =>
  Effect.try({
    try: () => crypto.randomBytes(length),
    catch: (error) => new Errors.HashingError({
      message: "Failed to generate random secret",
      cause: error
    })
  })

/**
 * Encode bytes to base32 (RFC 4648)
 * Used for encoding OTP secrets
 */
export const encodeBase32 = (buffer: Buffer): string => {
  const base32Chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"
  let bits = 0
  let value = 0
  let output = ""

  for (let i = 0; i < buffer.length; i++) {
    value = (value << 8) | buffer[i]
    bits += 8

    while (bits >= 5) {
      output += base32Chars[(value >>> (bits - 5)) & 31]
      bits -= 5
    }
  }

  if (bits > 0) {
    output += base32Chars[(value << (5 - bits)) & 31]
  }

  return output
}

/**
 * Decode base32 string to bytes (RFC 4648)
 */
export const decodeBase32 = (base32: string): Effect.Effect<Buffer, Errors.HashingError> =>
  Effect.try({
    try: () => {
      const base32Chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"
      const cleanBase32 = base32.toUpperCase().replace(/[=\s]/g, "")
      
      let bits = 0
      let value = 0
      const output: number[] = []

      for (let i = 0; i < cleanBase32.length; i++) {
        const idx = base32Chars.indexOf(cleanBase32[i])
        if (idx === -1) {
          throw new Error(`Invalid base32 character: ${cleanBase32[i]}`)
        }

        value = (value << 5) | idx
        bits += 5

        if (bits >= 8) {
          output.push((value >>> (bits - 8)) & 255)
          bits -= 8
        }
      }

      return Buffer.from(output)
    },
    catch: (error) => new Errors.HashingError({
      message: "Failed to decode base32 string",
      cause: error
    })
  })

/**
 * Generate HMAC-based One-Time Password (HOTP)
 * Following RFC 4226
 * 
 * @param secret - Base32-encoded secret or raw Buffer
 * @param counter - Counter value
 * @param config - HOTP configuration
 * @returns Effect that produces the OTP string
 */
export const generateHOTP = (
  secret: string | Buffer,
  counter: number,
  config?: HOTPConfig
): Effect.Effect<string, Errors.HashingError> =>
  Effect.gen(function* () {
    const digits = config?.digits ?? 6
    const algorithm = config?.algorithm ?? "sha1"

    // Decode secret if it's a string
    const secretBuffer = typeof secret === "string"
      ? yield* decodeBase32(secret)
      : secret

    // Create counter buffer (8 bytes, big-endian)
    const counterBuffer = Buffer.alloc(8)
    counterBuffer.writeBigUInt64BE(BigInt(counter), 0)

    // Generate HMAC
    const hmac = crypto.createHmac(algorithm, secretBuffer)
    hmac.update(counterBuffer)
    const hash = hmac.digest()

    // Dynamic truncation (RFC 4226 Section 5.3)
    const offset = hash[hash.length - 1] & 0x0f
    const binary =
      ((hash[offset] & 0x7f) << 24) |
      ((hash[offset + 1] & 0xff) << 16) |
      ((hash[offset + 2] & 0xff) << 8) |
      (hash[offset + 3] & 0xff)

    // Generate OTP
    const otp = binary % Math.pow(10, digits)
    return otp.toString().padStart(digits, "0")
  })

/**
 * Verify HMAC-based One-Time Password (HOTP)
 * 
 * @param token - The OTP token to verify
 * @param secret - Base32-encoded secret or raw Buffer
 * @param counter - Counter value
 * @param config - HOTP configuration
 * @returns Effect that produces true if valid, false otherwise
 */
export const verifyHOTP = (
  token: string,
  secret: string | Buffer,
  counter: number,
  config?: HOTPConfig
): Effect.Effect<boolean, Errors.HashingError> =>
  Effect.gen(function* () {
    const expectedToken = yield* generateHOTP(secret, counter, config)
    
    // Timing-safe comparison
    if (token.length !== expectedToken.length) {
      return false
    }
    
    return crypto.timingSafeEqual(
      Buffer.from(token),
      Buffer.from(expectedToken)
    )
  })

/**
 * Generate Time-based One-Time Password (TOTP)
 * Following RFC 6238
 * 
 * @param secret - Base32-encoded secret or raw Buffer
 * @param config - TOTP configuration
 * @returns Effect that produces the OTP string
 */
export const generateTOTP = (
  secret: string | Buffer,
  config?: TOTPConfig
): Effect.Effect<string, Errors.HashingError> => {
  const period = config?.period ?? 30
  const currentTime = Math.floor(Date.now() / 1000)
  const counter = Math.floor(currentTime / period)

  return generateHOTP(secret, counter, {
    digits: config?.digits,
    algorithm: config?.algorithm
  })
}

/**
 * Verify Time-based One-Time Password (TOTP)
 * Checks current time step and adjacent time steps within the window
 * 
 * @param token - The OTP token to verify
 * @param secret - Base32-encoded secret or raw Buffer
 * @param config - TOTP configuration
 * @returns Effect that produces true if valid, false otherwise
 */
export const verifyTOTP = (
  token: string,
  secret: string | Buffer,
  config?: TOTPConfig
): Effect.Effect<boolean, Errors.HashingError> =>
  Effect.gen(function* () {
    const period = config?.period ?? 30
    const window = config?.window ?? 1
    const currentTime = Math.floor(Date.now() / 1000)
    const currentCounter = Math.floor(currentTime / period)

    // Check current time step and adjacent steps within window
    for (let i = -window; i <= window; i++) {
      const counter = currentCounter + i
      const expectedToken = yield* generateHOTP(secret, counter, {
        digits: config?.digits,
        algorithm: config?.algorithm
      })

      // Timing-safe comparison
      if (token.length === expectedToken.length) {
        const isValid = crypto.timingSafeEqual(
          Buffer.from(token),
          Buffer.from(expectedToken)
        )
        if (isValid) {
          return true
        }
      }
    }

    return false
  })

/**
 * Generate an OTP URI for QR code generation
 * Compatible with Google Authenticator and other OTP apps
 * 
 * @param params - OTP URI parameters
 * @returns The otpauth:// URI string
 */
export const generateOTPURI = (params: OTPURIParams): string => {
  const { type, label, issuer, secret, counter, period, digits, algorithm } = params

  // Encode label and issuer for URI
  const encodedLabel = encodeURIComponent(label)
  const encodedIssuer = encodeURIComponent(issuer)

  // Build URI
  let uri = `otpauth://${type}/${encodedIssuer}:${encodedLabel}?secret=${secret}&issuer=${encodedIssuer}`

  // Add optional parameters
  if (type === "hotp" && counter !== undefined) {
    uri += `&counter=${counter}`
  }
  if (type === "totp" && period !== undefined && period !== 30) {
    uri += `&period=${period}`
  }
  if (digits !== undefined && digits !== 6) {
    uri += `&digits=${digits}`
  }
  if (algorithm !== undefined && algorithm !== "sha1") {
    uri += `&algorithm=${algorithm.toUpperCase()}`
  }

  return uri
}

/**
 * Generate a random OTP secret and return it as a base32 string
 * 
 * @param length - Number of bytes to generate (default: 20)
 * @returns Effect that produces a base32-encoded secret
 */
export const generateBase32Secret = (length: number = 20): Effect.Effect<string, Errors.HashingError> =>
  Effect.gen(function* () {
    const bytes = yield* generateSecret(length)
    return encodeBase32(bytes)
  })
