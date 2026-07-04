---
title: "PhoneOtp"
description: "API reference for the PhoneOtp module."
---

## PhoneOtp overview

Phone number authentication via SMS one-time passwords.

Mirrors `EmailOtp.ts` (hashed OTP at rest, attempt limiting, purpose scoping,
anti-enumeration) — only the channel (SMS) and the user-lookup key (phone
number) differ. Two purposes are supported: `sign-in` and
`phone-verification`.

Convention: phone identity lives in `attributes.phoneNumber` /
`attributes.phoneNumberVerified` (there is no first-class `User.phoneNumber`
column). Use {@link getPhoneNumber} to read it.

E.164 normalization is application policy: the default `normalizePhoneNumber`
only trims whitespace. Apps should plug a real E.164 normalizer via config.

---

<h2 class="text-delta">Table of contents</h2>

- [utils](#utils)
  - [PhoneOtpAuthResult (interface)](#phoneotpauthresult-interface)
  - [PhoneOtpConfig (interface)](#phoneotpconfig-interface)
  - [PhoneOtpCreateUserInput (interface)](#phoneotpcreateuserinput-interface)
  - [PhoneOtpError (class)](#phoneotperror-class)
  - [PhoneOtpPurpose (type alias)](#phoneotppurpose-type-alias)
  - [PhoneOtpRecord (interface)](#phoneotprecord-interface)
  - [PhoneOtpService (class)](#phoneotpservice-class)
  - [PhoneOtpServiceShape (interface)](#phoneotpserviceshape-interface)
  - [PhoneOtpSignInOptions (interface)](#phoneotpsigninoptions-interface)
  - [PhoneOtpStore (class)](#phoneotpstore-class)
  - [PhoneOtpStoreShape (interface)](#phoneotpstoreshape-interface)
  - [PhoneOtpUserStore (class)](#phoneotpuserstore-class)
  - [PhoneOtpUserStoreShape (interface)](#phoneotpuserstoreshape-interface)
  - [getPhoneNumber](#getphonenumber)
  - [makePhoneOtpService](#makephoneotpservice)

---

# utils

## PhoneOtpAuthResult (interface)

**Signature**

```ts
export interface PhoneOtpAuthResult {
  readonly user: Types.User;
  readonly session: Types.Session;
}
```

## PhoneOtpConfig (interface)

**Signature**

```ts
export interface PhoneOtpConfig {
  readonly otpLength?: number; // Default: 6 digits
  readonly expiresIn?: number; // Default: 5 minutes
  readonly maxAttempts?: number; // Default: 3
  readonly disableSignUp?: boolean; // Default: false
  readonly sendOtp: (
    phoneNumber: string,
    otp: string,
    purpose: PhoneOtpPurpose,
  ) => Effect.Effect<void, unknown>;
  /**
   * Normalize a raw phone number before storage/lookup. Default trims
   * whitespace only — plug a real E.164 normalizer here.
   */
  readonly normalizePhoneNumber?: (raw: string) => Effect.Effect<string, Errors.AuthError>;
}
```

## PhoneOtpCreateUserInput (interface)

Input for creating a user from a verified phone number.

**Signature**

```ts
export interface PhoneOtpCreateUserInput {
  readonly phoneNumber: string;
  readonly phoneNumberVerified: boolean;
  readonly name?: string;
}
```

## PhoneOtpError (class)

Error raised by phone OTP verification failures.

**Signature**

```ts
export declare class PhoneOtpError
```

## PhoneOtpPurpose (type alias)

The purposes a phone OTP can be issued for.

**Signature**

```ts
export type PhoneOtpPurpose = "sign-in" | "phone-verification";
```

## PhoneOtpRecord (interface)

Stored phone OTP record. Only the SHA-256 hash of the code is persisted.

**Signature**

```ts
export interface PhoneOtpRecord {
  readonly phoneNumber: string;
  readonly otpHash: string;
  readonly purpose: PhoneOtpPurpose;
  readonly attempts: number;
  readonly createdAt: number;
  readonly expiresAt: number;
}
```

## PhoneOtpService (class)

**Signature**

```ts
export declare class PhoneOtpService
```

## PhoneOtpServiceShape (interface)

**Signature**

```ts
export interface PhoneOtpServiceShape {
  /**
   * Generate an OTP for the given phone number + purpose (replacing any
   * outstanding one) and send it. Only a SHA-256 hash of the code is stored.
   * Anti-enumeration: for `sign-in` with sign-up disabled and no user, this
   * succeeds silently without sending.
   */
  readonly send: (
    phoneNumber: string,
    purpose: PhoneOtpPurpose,
  ) => Effect.Effect<void, PhoneOtpError | Errors.AuthError, PhoneOtpStore | PhoneOtpUserStore>;

  /**
   * Verify a `sign-in` OTP (single use) and sign the user in, creating a new
   * `phoneNumberVerified: true` user when none exists (unless `disableSignUp`).
   */
  readonly signIn: (
    phoneNumber: string,
    otp: string,
    options?: PhoneOtpSignInOptions,
  ) => Effect.Effect<
    PhoneOtpAuthResult,
    PhoneOtpError | Errors.AuthError | HookError,
    PhoneOtpStore | PhoneOtpUserStore | SessionManager | Hooks
  >;

  /**
   * Verify a `phone-verification` OTP (single use) for an existing user and
   * mark their phone number verified.
   */
  readonly verifyPhoneNumber: (
    userId: string,
    phoneNumber: string,
    otp: string,
  ) => Effect.Effect<
    Types.User,
    PhoneOtpError | Errors.AuthError | Errors.UserNotFoundError,
    PhoneOtpStore | PhoneOtpUserStore
  >;
}
```

## PhoneOtpSignInOptions (interface)

**Signature**

```ts
export interface PhoneOtpSignInOptions {
  readonly sessionAttributes?: Record<string, unknown>;
}
```

## PhoneOtpStore (class)

**Signature**

```ts
export declare class PhoneOtpStore
```

## PhoneOtpStoreShape (interface)

Persistence for phone OTPs, keyed by the (normalized phoneNumber, purpose)
pair; `upsert` replaces any existing record for the pair.

**Signature**

```ts
export interface PhoneOtpStoreShape {
  readonly upsert: (record: PhoneOtpRecord) => Effect.Effect<PhoneOtpRecord, Errors.AuthError>;
  readonly get: (
    phoneNumber: string,
    purpose: PhoneOtpPurpose,
  ) => Effect.Effect<PhoneOtpRecord | null, Errors.AuthError>;
  readonly delete: (
    phoneNumber: string,
    purpose: PhoneOtpPurpose,
  ) => Effect.Effect<void, Errors.AuthError>;
  readonly incrementAttempts: (
    phoneNumber: string,
    purpose: PhoneOtpPurpose,
  ) => Effect.Effect<number, Errors.AuthError>;
}
```

## PhoneOtpUserStore (class)

**Signature**

```ts
export declare class PhoneOtpUserStore
```

## PhoneOtpUserStoreShape (interface)

User lookup/creation keyed by phone number. Implementers store the number in
`attributes.phoneNumber` and the verification flag in
`attributes.phoneNumberVerified`.

**Signature**

```ts
export interface PhoneOtpUserStoreShape {
  readonly getUserByPhoneNumber: (
    phoneNumber: string,
  ) => Effect.Effect<Types.User | null, Errors.AuthError>;
  readonly createUser: (
    input: PhoneOtpCreateUserInput,
  ) => Effect.Effect<Types.User, Errors.AuthError>;
  readonly setPhoneNumberVerified: (
    userId: string,
    phoneNumber: string,
  ) => Effect.Effect<Types.User, Errors.AuthError | Errors.UserNotFoundError>;
}
```

## getPhoneNumber

Read the phone number from a user's attributes, or `null`.

**Signature**

```ts
export declare const getPhoneNumber: (user: Types.User) => string | null;
```

## makePhoneOtpService

**Signature**

```ts
export declare const makePhoneOtpService: (
  config: PhoneOtpConfig,
) => Effect.Effect<PhoneOtpServiceShape, never>;
```
