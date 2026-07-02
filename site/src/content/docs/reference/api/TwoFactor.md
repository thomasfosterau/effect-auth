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
  - [PendingTwoFactorStore](#pendingtwofactorstore)
  - [PendingTwoFactorStore (interface)](#pendingtwofactorstore-interface)
  - [PendingTwoFactorStoreTag (class)](#pendingtwofactorstoretag-class)
  - [TwoFactorChallenge (interface)](#twofactorchallenge-interface)
  - [TwoFactorConfig (interface)](#twofactorconfig-interface)
  - [TwoFactorEnableResult (interface)](#twofactorenableresult-interface)
  - [TwoFactorError (class)](#twofactorerror-class)
  - [TwoFactorGateLayer](#twofactorgatelayer)
  - [TwoFactorRecord (interface)](#twofactorrecord-interface)
  - [TwoFactorService](#twofactorservice)
  - [TwoFactorService (interface)](#twofactorservice-interface)
  - [TwoFactorServiceLayer](#twofactorservicelayer)
  - [TwoFactorServiceTag (class)](#twofactorservicetag-class)
  - [TwoFactorStore](#twofactorstore)
  - [TwoFactorStore (interface)](#twofactorstore-interface)
  - [TwoFactorStoreTag (class)](#twofactorstoretag-class)
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

## PendingTwoFactorStore

**Signature**

```ts
export declare const PendingTwoFactorStore: typeof PendingTwoFactorStoreTag;
```

## PendingTwoFactorStore (interface)

Storage interface for pending two-factor challenges

**Signature**

```ts
export interface PendingTwoFactorStore {
  readonly create: (pending: PendingTwoFactor) => Effect.Effect<PendingTwoFactor, Errors.AuthError>;
  readonly get: (token: string) => Effect.Effect<PendingTwoFactor | null, Errors.AuthError>;
  readonly delete: (token: string) => Effect.Effect<void, Errors.AuthError>;
}
```

## PendingTwoFactorStoreTag (class)

**Signature**

```ts
export declare class PendingTwoFactorStoreTag
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

Provides the {@link SecondFactorGateTag} seam so password sign-in returns a
two-factor challenge (instead of a session) for enrolled users.

The gate's methods are self-contained (`R = never`), so the two-factor
stores are captured from context when the layer is built:

```ts
const services = Layer.mergeAll(
  EmailPasswordServiceLayer(),
  TwoFactorGateLayer.pipe(
    Layer.provide(TwoFactorServiceLayer({ issuer: "MyApp" })),
    Layer.provide(twoFactorStores),
  ),
);
```

**Signature**

```ts
export declare const TwoFactorGateLayer: Layer.Layer<
  SecondFactorGateTag,
  never,
  TwoFactorServiceTag | TwoFactorStoreTag | PendingTwoFactorStoreTag
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

## TwoFactorService

**Signature**

```ts
export declare const TwoFactorService: typeof TwoFactorServiceTag;
```

## TwoFactorService (interface)

Two-factor authentication service

**Signature**

```ts
export interface TwoFactorService {
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
    TwoFactorStoreTag | EmailPasswordStoreTag | PasswordHasherTag | UserStoreTag
  >;

  /**
   * Confirm enrollment with a TOTP code generated from the stored secret.
   * Marks the record verified; two-factor is only enforced once verified.
   */
  readonly confirmEnable: (
    userId: string,
    code: string,
  ) => Effect.Effect<
    void,
    TwoFactorError | Errors.HashingError | Errors.AuthError,
    TwoFactorStoreTag
  >;

  /**
   * Disable two-factor after re-verifying the user's password.
   */
  readonly disable: (
    userId: string,
    password: string,
  ) => Effect.Effect<
    void,
    Errors.InvalidCredentialsError | Errors.HashingError | Errors.AuthError,
    TwoFactorStoreTag | EmailPasswordStoreTag | PasswordHasherTag
  >;

  /**
   * Whether the user has a verified two-factor record.
   */
  readonly isEnabled: (
    userId: string,
  ) => Effect.Effect<boolean, Errors.AuthError, TwoFactorStoreTag>;

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
    TwoFactorStoreTag | PendingTwoFactorStoreTag
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
    TwoFactorStoreTag | PendingTwoFactorStoreTag | SessionManagerTag | Hooks
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
    TwoFactorStoreTag | PendingTwoFactorStoreTag | SessionManagerTag | Hooks
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
    TwoFactorStoreTag | EmailPasswordStoreTag | PasswordHasherTag
  >;
}
```

## TwoFactorServiceLayer

**Signature**

```ts
export declare const TwoFactorServiceLayer: (
  config: TwoFactorConfig,
) => Layer.Layer<TwoFactorServiceTag, never, never>;
```

## TwoFactorServiceTag (class)

**Signature**

```ts
export declare class TwoFactorServiceTag
```

## TwoFactorStore

**Signature**

```ts
export declare const TwoFactorStore: typeof TwoFactorStoreTag;
```

## TwoFactorStore (interface)

Storage interface for two-factor records

**Signature**

```ts
export interface TwoFactorStore {
  readonly get: (userId: string) => Effect.Effect<TwoFactorRecord | null, Errors.AuthError>;
  readonly upsert: (record: TwoFactorRecord) => Effect.Effect<TwoFactorRecord, Errors.AuthError>;
  readonly delete: (userId: string) => Effect.Effect<void, Errors.AuthError>;
}
```

## TwoFactorStoreTag (class)

**Signature**

```ts
export declare class TwoFactorStoreTag
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
) => Effect.Effect<TwoFactorService, never>;
```
