---
title: "EmailOtp"
description: "API reference for the EmailOtp module."
---

## EmailOtp overview

Email OTP sign-in and verification for effect-auth.

Implements one-time numeric codes delivered by email (better-auth
"email OTP" parity) for three purposes: sign-in, email verification, and
password reset. Only a SHA-256 hash of the code is stored; codes are
single-use, expire, and are attempt-limited. Comparison is constant-time.

---

<h2 class="text-delta">Table of contents</h2>

- [utils](#utils)
  - [EmailOtpAuthResult (interface)](#emailotpauthresult-interface)
  - [EmailOtpCheckResult (interface)](#emailotpcheckresult-interface)
  - [EmailOtpConfig (interface)](#emailotpconfig-interface)
  - [EmailOtpCreateUserInput (interface)](#emailotpcreateuserinput-interface)
  - [EmailOtpError (class)](#emailotperror-class)
  - [EmailOtpPurpose (type alias)](#emailotppurpose-type-alias)
  - [EmailOtpRecord (interface)](#emailotprecord-interface)
  - [EmailOtpService (class)](#emailotpservice-class)
  - [EmailOtpServiceShape (interface)](#emailotpserviceshape-interface)
  - [EmailOtpSignInOptions (interface)](#emailotpsigninoptions-interface)
  - [EmailOtpStore (class)](#emailotpstore-class)
  - [EmailOtpStoreShape (interface)](#emailotpstoreshape-interface)
  - [EmailOtpUserStore (class)](#emailotpuserstore-class)
  - [EmailOtpUserStoreShape (interface)](#emailotpuserstoreshape-interface)
  - [generateOtp](#generateotp)
  - [hashOtp](#hashotp)
  - [makeEmailOtpService](#makeemailotpservice)

---

# utils

## EmailOtpAuthResult (interface)

Result of a successful email OTP sign-in

**Signature**

```ts
export interface EmailOtpAuthResult {
  readonly user: Types.User;
  readonly session: Types.Session;
}
```

## EmailOtpCheckResult (interface)

Result of a successful generic OTP check

**Signature**

```ts
export interface EmailOtpCheckResult {
  readonly email: string;
  readonly verified: true;
}
```

## EmailOtpConfig (interface)

Email OTP service configuration

**Signature**

```ts
export interface EmailOtpConfig {
  readonly otpLength?: number; // Default: 6 digits
  readonly expiresIn?: number; // Default: 5 minutes
  readonly maxAttempts?: number; // Default: 3
  readonly disableSignUp?: boolean; // Default: false
  readonly sendVerificationOtp: (
    email: string,
    otp: string,
    purpose: EmailOtpPurpose,
  ) => Effect.Effect<void, Errors.AuthError>;
}
```

## EmailOtpCreateUserInput (interface)

Input for creating a user during email OTP sign-in

**Signature**

```ts
export interface EmailOtpCreateUserInput {
  readonly email: string;
  readonly emailVerified: boolean;
  readonly name?: string;
}
```

## EmailOtpError (class)

Email OTP error

**Signature**

```ts
export declare class EmailOtpError
```

## EmailOtpPurpose (type alias)

The purposes an email OTP can be issued for

**Signature**

```ts
export type EmailOtpPurpose = "sign-in" | "email-verification" | "forget-password";
```

## EmailOtpRecord (interface)

Stored email OTP record. Only the SHA-256 hash of the code is persisted.

**Signature**

```ts
export interface EmailOtpRecord {
  readonly email: string;
  readonly otpHash: string;
  readonly purpose: EmailOtpPurpose;
  readonly attempts: number;
  readonly createdAt: number;
  readonly expiresAt: number;
}
```

## EmailOtpService (class)

**Signature**

```ts
export declare class EmailOtpService
```

## EmailOtpServiceShape (interface)

Email OTP service

**Signature**

```ts
export interface EmailOtpServiceShape {
  /**
   * Generate an OTP for the given email + purpose (replacing any outstanding
   * one) and send it. Only a SHA-256 hash of the code is stored.
   *
   * Anti-enumeration: for `"sign-in"` with sign-up disabled and no matching
   * user, and for `"forget-password"` with no matching user, this succeeds
   * silently without sending anything.
   */
  readonly send: (
    email: string,
    purpose: EmailOtpPurpose,
  ) => Effect.Effect<void, Errors.AuthError | EmailOtpError, EmailOtpStore | EmailOtpUserStore>;

  /**
   * Verify a `"sign-in"` OTP and create a session. Users created here are
   * marked `emailVerified: true` (the OTP proves ownership of the email).
   */
  readonly signIn: (
    email: string,
    otp: string,
    options?: EmailOtpSignInOptions,
  ) => Effect.Effect<
    EmailOtpAuthResult,
    EmailOtpError | Errors.AuthError | HookError,
    EmailOtpStore | EmailOtpUserStore | SessionManager | Hooks
  >;

  /**
   * Verify an OTP for any purpose (single use) without creating a session.
   * Intended for `"email-verification"` and `"forget-password"` flows to
   * consume before performing their own follow-up work.
   */
  readonly check: (
    email: string,
    otp: string,
    purpose: EmailOtpPurpose,
  ) => Effect.Effect<EmailOtpCheckResult, EmailOtpError | Errors.AuthError, EmailOtpStore>;
}
```

## EmailOtpSignInOptions (interface)

Options for email OTP sign-in

**Signature**

```ts
export interface EmailOtpSignInOptions {
  readonly sessionAttributes?: Record<string, unknown>;
}
```

## EmailOtpStore (class)

Email OTP store context tag

**Signature**

```ts
export declare class EmailOtpStore
```

## EmailOtpStoreShape (interface)

Storage interface for email OTPs. There is at most one active OTP per
email + purpose pair; `upsert` replaces any existing record for the pair.

**Signature**

```ts
export interface EmailOtpStoreShape {
  readonly upsert: (record: EmailOtpRecord) => Effect.Effect<EmailOtpRecord, Errors.AuthError>;
  readonly get: (
    email: string,
    purpose: EmailOtpPurpose,
  ) => Effect.Effect<EmailOtpRecord | null, Errors.AuthError>;
  readonly delete: (
    email: string,
    purpose: EmailOtpPurpose,
  ) => Effect.Effect<void, Errors.AuthError>;
  readonly incrementAttempts: (
    email: string,
    purpose: EmailOtpPurpose,
  ) => Effect.Effect<number, Errors.AuthError>;
}
```

## EmailOtpUserStore (class)

Email OTP user store context tag

**Signature**

```ts
export declare class EmailOtpUserStore
```

## EmailOtpUserStoreShape (interface)

User store interface for email OTP sign-in

**Signature**

```ts
export interface EmailOtpUserStoreShape {
  readonly getUserByEmail: (email: string) => Effect.Effect<Types.User | null, Errors.AuthError>;
  readonly createUser: (
    input: EmailOtpCreateUserInput,
  ) => Effect.Effect<Types.User, Errors.AuthError>;
}
```

## generateOtp

Generate a numeric OTP with crypto-secure randomness (one uniform
`crypto.randomInt` draw per digit).

**Signature**

```ts
export declare const generateOtp: (length: number) => Effect.Effect<string, Errors.AuthError>;
```

## hashOtp

SHA-256 hex digest of an OTP code

**Signature**

```ts
export declare const hashOtp: (otp: string) => string;
```

## makeEmailOtpService

Create an email OTP service

**Signature**

```ts
export declare const makeEmailOtpService: (
  config: EmailOtpConfig,
) => Effect.Effect<EmailOtpServiceShape, never>;
```
