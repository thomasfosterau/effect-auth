---
title: "Otp"
description: "API reference for the Otp module."
---

## Otp overview

---

<h2 class="text-delta">Table of contents</h2>

- [utils](#utils)
  - [HOTPConfig (interface)](#hotpconfig-interface)
  - [OTPURIParams (interface)](#otpuriparams-interface)
  - [TOTPConfig (interface)](#totpconfig-interface)
  - [decodeBase32](#decodebase32)
  - [encodeBase32](#encodebase32)
  - [generateBase32Secret](#generatebase32secret)
  - [generateHOTP](#generatehotp)
  - [generateOTPURI](#generateotpuri)
  - [generateSecret](#generatesecret)
  - [generateTOTP](#generatetotp)
  - [verifyHOTP](#verifyhotp)
  - [verifyTOTP](#verifytotp)

---

# utils

## HOTPConfig (interface)

Configuration for HOTP generation

**Signature**

```ts
export interface HOTPConfig {
  /** Number of digits in the OTP (default: 6) */
  readonly digits?: number;
  /** HMAC algorithm to use (default: "sha1") */
  readonly algorithm?: "sha1" | "sha256" | "sha512";
}
```

## OTPURIParams (interface)

OTP URI parameters for generating QR codes

**Signature**

```ts
export interface OTPURIParams {
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
```

## TOTPConfig (interface)

Configuration for TOTP generation

**Signature**

```ts
export interface TOTPConfig {
  /** Time step in seconds (default: 30) */
  readonly period?: number;
  /** Number of digits in the OTP (default: 6) */
  readonly digits?: number;
  /** HMAC algorithm to use (default: "sha1") */
  readonly algorithm?: "sha1" | "sha256" | "sha512";
  /** Number of periods to check before and after current time (default: 1) */
  readonly window?: number;
}
```

## decodeBase32

Decode base32 string to bytes (RFC 4648)

**Signature**

```ts
export declare const decodeBase32: (base32: string) => Effect.Effect<Buffer, Errors.HashingError>;
```

## encodeBase32

Encode bytes to base32 (RFC 4648)
Used for encoding OTP secrets

**Signature**

```ts
export declare const encodeBase32: (buffer: Buffer) => string;
```

## generateBase32Secret

Generate a random OTP secret and return it as a base32 string

**Signature**

```ts
export declare const generateBase32Secret: (
  length?: number,
) => Effect.Effect<string, Errors.HashingError>;
```

## generateHOTP

Generate HMAC-based One-Time Password (HOTP)
Following RFC 4226

**Signature**

```ts
export declare const generateHOTP: (
  secret: string | Buffer,
  counter: number,
  config?: HOTPConfig,
) => Effect.Effect<string, Errors.HashingError>;
```

## generateOTPURI

Generate an OTP URI for QR code generation
Compatible with Google Authenticator and other OTP apps

**Signature**

```ts
export declare const generateOTPURI: (params: OTPURIParams) => string;
```

## generateSecret

Generate cryptographically secure random bytes for OTP secret

**Signature**

```ts
export declare const generateSecret: (
  length?: number,
) => Effect.Effect<Buffer, Errors.HashingError>;
```

## generateTOTP

Generate Time-based One-Time Password (TOTP)
Following RFC 6238

**Signature**

```ts
export declare const generateTOTP: (
  secret: string | Buffer,
  config?: TOTPConfig,
) => Effect.Effect<string, Errors.HashingError>;
```

## verifyHOTP

Verify HMAC-based One-Time Password (HOTP)

**Signature**

```ts
export declare const verifyHOTP: (
  token: string,
  secret: string | Buffer,
  counter: number,
  config?: HOTPConfig,
) => Effect.Effect<boolean, Errors.HashingError>;
```

## verifyTOTP

Verify Time-based One-Time Password (TOTP)
Checks current time step and adjacent time steps within the window

**Signature**

```ts
export declare const verifyTOTP: (
  token: string,
  secret: string | Buffer,
  config?: TOTPConfig,
) => Effect.Effect<boolean, Errors.HashingError>;
```
