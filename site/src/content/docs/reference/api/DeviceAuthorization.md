---
title: "DeviceAuthorization"
description: "API reference for the DeviceAuthorization module."
---

## DeviceAuthorization overview

Device Authorization Grant (RFC 8628) for input-constrained devices (CLIs,
TVs). The device requests a `device_code` + short human-typable `user_code`,
shows the user a verification URL, and polls the token endpoint while the
user approves the code on a second device.

House module pattern: store tag + `Context.Service` tag + `make*` +
`*ServiceLayer`, module-local `Data.TaggedError`s, epoch-ms timestamps.

---

<h2 class="text-delta">Table of contents</h2>

- [utils](#utils)
  - [DeviceAuthorizationConfig (interface)](#deviceauthorizationconfig-interface)
  - [DeviceAuthorizationRecord (interface)](#deviceauthorizationrecord-interface)
  - [DeviceAuthorizationService (class)](#deviceauthorizationservice-class)
  - [DeviceAuthorizationServiceShape (interface)](#deviceauthorizationserviceshape-interface)
  - [DeviceAuthorizationStatus (type alias)](#deviceauthorizationstatus-type-alias)
  - [DeviceAuthorizationStore (class)](#deviceauthorizationstore-class)
  - [DeviceAuthorizationStoreShape (interface)](#deviceauthorizationstoreshape-interface)
  - [DeviceBeginResult (interface)](#devicebeginresult-interface)
  - [DeviceCodeError (class)](#devicecodeerror-class)
  - [DevicePollError (class)](#devicepollerror-class)
  - [DevicePollResult (interface)](#devicepollresult-interface)
  - [makeDeviceAuthorizationService](#makedeviceauthorizationservice)
  - [normalizeUserCode](#normalizeusercode)

---

# utils

## DeviceAuthorizationConfig (interface)

**Signature**

```ts
export interface DeviceAuthorizationConfig {
  /** URL where the user enters their code. Shown to the device. */
  readonly verificationUri: string;
  /** Request lifetime in ms. Default 30 minutes. */
  readonly expiresIn?: number;
  /** Minimum polling interval in seconds. Default 5. */
  readonly interval?: number;
  /** Number of user-code characters (grouped in two halves). Default 8. */
  readonly userCodeLength?: number;
  /** Alphabet for the user code (ambiguous characters excluded by default). */
  readonly userCodeAlphabet?: string;
}
```

## DeviceAuthorizationRecord (interface)

A stored device authorization request. Timestamps are epoch-ms.

**Signature**

```ts
export interface DeviceAuthorizationRecord {
  readonly deviceCode: string;
  readonly userCode: string;
  readonly clientId?: string;
  readonly scopes?: readonly string[];
  readonly status: DeviceAuthorizationStatus;
  readonly userId?: string;
  readonly createdAt: number;
  readonly expiresAt: number;
  readonly lastPolledAt: number;
  readonly interval: number;
}
```

## DeviceAuthorizationService (class)

**Signature**

```ts
export declare class DeviceAuthorizationService
```

## DeviceAuthorizationServiceShape (interface)

**Signature**

```ts
export interface DeviceAuthorizationServiceShape {
  /** Start a device authorization request. */
  readonly begin: (options?: {
    readonly clientId?: string;
    readonly scopes?: readonly string[];
  }) => Effect.Effect<DeviceBeginResult, Errors.AuthError, DeviceAuthorizationStore>;

  /**
   * Poll for completion. Returns a session once approved; otherwise fails with
   * the RFC 8628 error (`authorization_pending`, `slow_down`, `expired_token`,
   * `access_denied`).
   */
  readonly poll: (
    deviceCode: string,
  ) => Effect.Effect<
    DevicePollResult,
    | DevicePollError
    | Errors.AuthError
    | Errors.SessionNotFoundError
    | Errors.SessionExpiredError
    | Errors.UserNotFoundError
    | HookError,
    DeviceAuthorizationStore | SessionManager | Hooks
  >;

  /** Approve a user code (called from an authenticated verification page). */
  readonly approve: (
    userCode: string,
    userId: string,
  ) => Effect.Effect<void, DeviceCodeError | Errors.AuthError, DeviceAuthorizationStore>;

  /** Deny a user code. */
  readonly deny: (
    userCode: string,
  ) => Effect.Effect<void, DeviceCodeError | Errors.AuthError, DeviceAuthorizationStore>;
}
```

## DeviceAuthorizationStatus (type alias)

Lifecycle status of a device authorization request.

**Signature**

```ts
export type DeviceAuthorizationStatus = "pending" | "approved" | "denied";
```

## DeviceAuthorizationStore (class)

**Signature**

```ts
export declare class DeviceAuthorizationStore
```

## DeviceAuthorizationStoreShape (interface)

Persistence for device authorization requests.

**Signature**

```ts
export interface DeviceAuthorizationStoreShape {
  readonly create: (
    record: DeviceAuthorizationRecord,
  ) => Effect.Effect<DeviceAuthorizationRecord, Errors.AuthError>;
  readonly getByDeviceCode: (
    deviceCode: string,
  ) => Effect.Effect<DeviceAuthorizationRecord | null, Errors.AuthError>;
  readonly getByUserCode: (
    userCode: string,
  ) => Effect.Effect<DeviceAuthorizationRecord | null, Errors.AuthError>;
  readonly update: (
    record: DeviceAuthorizationRecord,
  ) => Effect.Effect<DeviceAuthorizationRecord, Errors.AuthError>;
  readonly delete: (deviceCode: string) => Effect.Effect<void, Errors.AuthError>;
}
```

## DeviceBeginResult (interface)

**Signature**

```ts
export interface DeviceBeginResult {
  readonly deviceCode: string;
  readonly userCode: string;
  readonly verificationUri: string;
  readonly expiresIn: number;
  readonly interval: number;
}
```

## DeviceCodeError (class)

Raised when a user code is unknown or has expired at approve/deny time.

**Signature**

```ts
export declare class DeviceCodeError
```

## DevicePollError (class)

RFC 8628 polling errors, mapped to the standard OAuth `error` codes.

**Signature**

```ts
export declare class DevicePollError
```

## DevicePollResult (interface)

**Signature**

```ts
export interface DevicePollResult {
  readonly user: Types.User;
  readonly session: Types.Session;
}
```

## makeDeviceAuthorizationService

**Signature**

```ts
export declare const makeDeviceAuthorizationService: (
  config: DeviceAuthorizationConfig,
) => Effect.Effect<DeviceAuthorizationServiceShape, never>;
```

## normalizeUserCode

Normalize a user code for lookup (uppercase, strip non-alphanumerics).

**Signature**

```ts
export declare const normalizeUserCode: (code: string) => string;
```
