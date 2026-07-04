---
title: "TwoFactor"
description: "API reference for the TwoFactor module."
---

## TwoFactor overview

Two-factor authentication (TOTP + backup codes) for effect-auth.

Mirrors better-auth's two-factor plugin: users enable 2FA by verifying
their password, receive a TOTP secret (as an otpauth:// URI for QR codes)
plus single-use backup codes, and must confirm with a valid TOTP code
before 2FA is considered active. Sign-in flows that detect an enabled
second factor create a short-lived pending challenge ("password OK,
awaiting second factor") which is redeemed with either a TOTP code or a
backup code to mint the session.

---

<h2 class="text-delta">Table of contents</h2>

- [utils](#utils)
  - [PendingTwoFactor (interface)](#pendingtwofactor-interface)
  - [PendingTwoFactorStore (class)](#pendingtwofactorstore-class)
  - [PendingTwoFactorStoreShape (interface)](#pendingtwofactorstoreshape-interface)
  - [TwoFactorChallenge (interface)](#twofactorchallenge-interface)
  - [TwoFactorConfig (interface)](#twofactorconfig-interface)
  - [TwoFactorEnableResult (interface)](#twofactorenableresult-interface)
  - [TwoFactorError (class)](#twofactorerror-class)
  - [TwoFactorGateLayer](#twofactorgatelayer)
  - [TwoFactorRecord (interface)](#twofactorrecord-interface)
  - [TwoFactorService (class)](#twofactorservice-class)
  - [TwoFactorServiceShape (interface)](#twofactorserviceshape-interface)
  - [TwoFactorStore (class)](#twofactorstore-class)
  - [TwoFactorStoreShape (interface)](#twofactorstoreshape-interface)
  - [TwoFactorVerifyOptions (interface)](#twofactorverifyoptions-interface)
  - [TwoFactorVerifyResult (interface)](#twofactorverifyresult-interface)
  - [hashBackupCode](#hashbackupcode)
  - [makeTwoFactorService](#maketwofactorservice)

---

# utils

## PendingTwoFactor (interface)

Short-lived "password OK, awaiting second factor" state created by
`beginChallenge` and redeemed (one-time) by `verifyTotp`/`verifyBackupCode`.

**Signature**

```ts
export interface PendingTwoFactor {
  readonly token: string;
  readonly userId: string;
  readonly expiresAt: number;
  readonly createdAt: number;
}
```

## PendingTwoFactorStore (class)

**Signature**

```ts
export declare class PendingTwoFactorStore
```

## PendingTwoFactorStoreShape (interface)

Storage interface for pending two-factor challenges

**Signature**

```ts
export interface PendingTwoFactorStoreShape {
  readonly create: (pending: PendingTwoFactor) => Effect.Effect<PendingTwoFactor, Errors.AuthError>;
  readonly get: (token: string) => Effect.Effect<PendingTwoFactor | null, Errors.AuthError>;
  readonly delete: (token: string) => Effect.Effect<void, Errors.AuthError>;
}
```

## TwoFactorChallenge (interface)

A pending second-factor challenge handed back to the caller.

**Signature**

```ts
export interface TwoFactorChallenge {
  readonly token: string;
  readonly expiresAt: number;
}
```

## TwoFactorConfig (interface)

Two-factor service configuration

**Signature**

```ts
export interface TwoFactorConfig {
  /** Issuer name embedded in the otpauth:// URI (e.g. your app name) */
  readonly issuer: string;
  /** TOTP parameters (period/digits/algorithm/window). Default: RFC 6238 defaults */
  readonly totp?: TOTPConfig;
  /** Number of backup codes to generate (default: 10) */
  readonly backupCodeCount?: number;
  /** Lifetime of a pending challenge in milliseconds (default: 5 minutes) */
  readonly pendingExpiresIn?: number;
  /**
   * Mark the record verified immediately on enable, skipping the
   * `confirmEnable` TOTP confirmation step (default: false).
   */
  readonly skipVerificationOnEnable?: boolean;
}
```

## TwoFactorEnableResult (interface)

Result of enabling two-factor: the secret and backup codes are returned
in plaintext exactly once — show them to the user, then discard.

**Signature**

```ts
export interface TwoFactorEnableResult {
  /** Base32-encoded TOTP secret */
  readonly secret: string;
  /** otpauth:// URI for QR code generation */
  readonly totpUri: string;
  /** Plaintext single-use backup codes (shown once) */
  readonly backupCodes: readonly string[];
}
```

## TwoFactorError (class)

Two-factor error

**Signature**

```ts
export declare class TwoFactorError
```

## TwoFactorGateLayer

Provides the {@link SecondFactorGate} seam so password sign-in returns a
two-factor challenge (instead of a session) for enrolled users.

The gate's methods are self-contained (`R = never`), so the two-factor
stores are captured from context when the layer is built:

```ts
const services = Layer.mergeAll(
  EmailPasswordService.layer(),
  TwoFactorGateLayer.pipe(
    Layer.provide(TwoFactorService.layer({ issuer: "MyApp" })),
    Layer.provide(twoFactorStores),
  ),
);
```

**Signature**

```ts
export declare const TwoFactorGateLayer: Layer.Layer<
  SecondFactorGate,
  never,
  TwoFactorService | TwoFactorStore | PendingTwoFactorStore
>;
```

## TwoFactorRecord (interface)

Persistent two-factor state for a user.

`backupCodes` holds sha256 hex digests of the (normalized) plaintext
codes — the plaintext is only ever returned once, at generation time.
`verified` stays `false` until the user confirms enrollment with a valid
TOTP code (unless `skipVerificationOnEnable` is set).

**Signature**

```ts
export interface TwoFactorRecord {
  readonly userId: string;
  /** Base32-encoded TOTP secret */
  readonly secret: string;
  /** sha256 hex hashes of the remaining (unused) backup codes */
  readonly backupCodes: readonly string[];
  /** False until the first successful TOTP confirmation */
  readonly verified: boolean;
  readonly createdAt: number;
}
```

## TwoFactorService (class)

**Signature**

```ts
export declare class TwoFactorService
```

## TwoFactorServiceShape (interface)

Two-factor authentication service

**Signature**

```ts
export interface TwoFactorServiceShape {
  /**
   * Enable two-factor for a user. Verifies the user's password, generates a
   * TOTP secret plus backup codes, and stores the record (unverified unless
   * `skipVerificationOnEnable`). Returns the plaintext secret, otpauth:// URI
   * (labelled with the user's email) and plaintext backup codes — shown once.
   */
  readonly enable: (
    userId: string,
    password: string,
  ) => Effect.Effect<
    TwoFactorEnableResult,
    | TwoFactorError
    | Errors.InvalidCredentialsError
    | Errors.HashingError
    | Errors.AuthError
    | Errors.UserNotFoundError,
    TwoFactorStore | EmailPasswordStore | PasswordHasher | UserStore
  >;

  /**
   * Confirm enrollment with a TOTP code generated from the stored secret.
   * Marks the record verified; two-factor is only enforced once verified.
   */
  readonly confirmEnable: (
    userId: string,
    code: string,
  ) => Effect.Effect<void, TwoFactorError | Errors.HashingError | Errors.AuthError, TwoFactorStore>;

  /**
   * Disable two-factor after re-verifying the user's password.
   */
  readonly disable: (
    userId: string,
    password: string,
  ) => Effect.Effect<
    void,
    Errors.InvalidCredentialsError | Errors.HashingError | Errors.AuthError,
    TwoFactorStore | EmailPasswordStore | PasswordHasher
  >;

  /**
   * Whether the user has a verified two-factor record.
   */
  readonly isEnabled: (userId: string) => Effect.Effect<boolean, Errors.AuthError, TwoFactorStore>;

  /**
   * Start a second-factor challenge for a user whose first factor (e.g.
   * password) already checked out. Returns a one-time pending token to be
   * redeemed with `verifyTotp` or `verifyBackupCode`.
   */
  readonly beginChallenge: (
    userId: string,
  ) => Effect.Effect<
    TwoFactorChallenge,
    TwoFactorError | Errors.AuthError,
    TwoFactorStore | PendingTwoFactorStore
  >;

  /**
   * Redeem a pending challenge with a TOTP code. On success the pending
   * token is consumed (one-time use) and a session is created.
   */
  readonly verifyTotp: (
    pendingToken: string,
    code: string,
    options?: TwoFactorVerifyOptions,
  ) => Effect.Effect<
    TwoFactorVerifyResult,
    TwoFactorError | Errors.HashingError | Errors.AuthError | HookError,
    TwoFactorStore | PendingTwoFactorStore | SessionManager | Hooks
  >;

  /**
   * Redeem a pending challenge with a backup code. The matched code is
   * removed from the record (single use) and a session is created.
   */
  readonly verifyBackupCode: (
    pendingToken: string,
    code: string,
    options?: TwoFactorVerifyOptions,
  ) => Effect.Effect<
    TwoFactorVerifyResult,
    TwoFactorError | Errors.AuthError | HookError,
    TwoFactorStore | PendingTwoFactorStore | SessionManager | Hooks
  >;

  /**
   * Replace all backup codes after re-verifying the user's password.
   * Returns the new plaintext codes (shown once); old codes are invalidated.
   */
  readonly regenerateBackupCodes: (
    userId: string,
    password: string,
  ) => Effect.Effect<
    readonly string[],
    TwoFactorError | Errors.InvalidCredentialsError | Errors.HashingError | Errors.AuthError,
    TwoFactorStore | EmailPasswordStore | PasswordHasher
  >;
}
```

## TwoFactorStore (class)

**Signature**

```ts
export declare class TwoFactorStore
```

## TwoFactorStoreShape (interface)

Storage interface for two-factor records

**Signature**

```ts
export interface TwoFactorStoreShape {
  readonly get: (userId: string) => Effect.Effect<TwoFactorRecord | null, Errors.AuthError>;
  readonly upsert: (record: TwoFactorRecord) => Effect.Effect<TwoFactorRecord, Errors.AuthError>;
  readonly delete: (userId: string) => Effect.Effect<void, Errors.AuthError>;
}
```

## TwoFactorVerifyOptions (interface)

**Signature**

```ts
export interface TwoFactorVerifyOptions {
  readonly sessionAttributes?: Record<string, unknown>;
}
```

## TwoFactorVerifyResult (interface)

Result of redeeming a pending challenge with a valid second factor.

**Signature**

```ts
export interface TwoFactorVerifyResult {
  readonly userId: string;
  readonly session: Types.Session;
}
```

## hashBackupCode

sha256 hex digest of a normalized backup code

**Signature**

```ts
export declare const hashBackupCode: (code: string) => string;
```

## makeTwoFactorService

Create a two-factor service

**Signature**

```ts
export declare const makeTwoFactorService: (
  config: TwoFactorConfig,
) => Effect.Effect<TwoFactorServiceShape, never>;
```
