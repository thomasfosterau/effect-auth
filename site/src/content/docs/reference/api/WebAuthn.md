---
title: "WebAuthn"
description: "API reference for the WebAuthn module."
---

## WebAuthn overview

WebAuthn types for passkey authentication
Following Copenhagen/Oslo guidelines for WebAuthn implementation

---

<h2 class="text-delta">Table of contents</h2>

- [utils](#utils)
  - [AuthenticationResponse (interface)](#authenticationresponse-interface)
  - [AuthenticationResult (interface)](#authenticationresult-interface)
  - [ChallengeStore](#challengestore)
  - [ChallengeStore (interface)](#challengestore-interface)
  - [ChallengeStoreTag (class)](#challengestoretag-class)
  - [CredentialStore](#credentialstore)
  - [CredentialStore (interface)](#credentialstore-interface)
  - [CredentialStoreTag (class)](#credentialstoretag-class)
  - [RegistrationResponse (interface)](#registrationresponse-interface)
  - [RegistrationResult (interface)](#registrationresult-interface)
  - [WebAuthnChallenge (interface)](#webauthnchallenge-interface)
  - [WebAuthnConfig (interface)](#webauthnconfig-interface)
  - [WebAuthnCredential (interface)](#webauthncredential-interface)
  - [WebAuthnService](#webauthnservice)
  - [WebAuthnService (interface)](#webauthnservice-interface)
  - [WebAuthnServiceLayer](#webauthnservicelayer)
  - [WebAuthnServiceTag (class)](#webauthnservicetag-class)
  - [WebAuthnUser (interface)](#webauthnuser-interface)
  - [base64UrlDecode](#base64urldecode)
  - [makeWebAuthnService](#makewebauthnservice)

---

# utils

## AuthenticationResponse (interface)

Authentication response from client

**Signature**

```ts
export interface AuthenticationResponse {
  /** Credential ID */
  credentialId: Uint8Array;
  /** Authenticator data from client */
  authenticatorData: Uint8Array;
  /** Client data JSON from client */
  clientDataJSON: Uint8Array;
  /** Signature from authenticator */
  signature: Uint8Array;
}
```

## AuthenticationResult (interface)

Result of successful authentication

**Signature**

```ts
export interface AuthenticationResult {
  /** The credential used for authentication */
  credential: WebAuthnCredential;
  /** Updated counter value */
  newCounter: number;
}
```

## ChallengeStore

**Signature**

```ts
export declare const ChallengeStore: typeof ChallengeStoreTag;
```

## ChallengeStore (interface)

WebAuthn challenge store interface
Implement this to store challenges in your database

**Signature**

```ts
export interface ChallengeStore {
  /** Store a challenge */
  create: (challenge: WebAuthnChallenge) => Effect.Effect<WebAuthnChallenge, Errors.AuthError>;
  /** Get a challenge by its value */
  get: (challenge: Uint8Array) => Effect.Effect<WebAuthnChallenge, Errors.ChallengeNotFoundError>;
  /** Delete a challenge */
  delete: (challenge: Uint8Array) => Effect.Effect<void, Errors.AuthError>;
}
```

## ChallengeStoreTag (class)

Context tag for ChallengeStore

**Signature**

```ts
export declare class ChallengeStoreTag
```

## CredentialStore

**Signature**

```ts
export declare const CredentialStore: typeof CredentialStoreTag;
```

## CredentialStore (interface)

WebAuthn credential store interface
Implement this to store credentials in your database

**Signature**

```ts
export interface CredentialStore {
  /** Store a credential */
  create: (credential: WebAuthnCredential) => Effect.Effect<WebAuthnCredential, Errors.AuthError>;
  /** Get a credential by ID */
  get: (credentialId: string) => Effect.Effect<WebAuthnCredential, Errors.CredentialNotFoundError>;
  /** Update a credential (e.g., counter) */
  update: (credential: WebAuthnCredential) => Effect.Effect<WebAuthnCredential, Errors.AuthError>;
  /** Delete a credential */
  delete: (credentialId: string) => Effect.Effect<void, Errors.AuthError>;
  /** Get all credentials for a user */
  getByUserId: (userId: string) => Effect.Effect<readonly WebAuthnCredential[], Errors.AuthError>;
}
```

## CredentialStoreTag (class)

Context tag for CredentialStore

**Signature**

```ts
export declare class CredentialStoreTag
```

## RegistrationResponse (interface)

Registration response from client

**Signature**

```ts
export interface RegistrationResponse {
  /** Credential ID */
  credentialId: Uint8Array;
  /** Attestation object from client */
  attestationObject: Uint8Array;
  /** Client data JSON from client */
  clientDataJSON: Uint8Array;
}
```

## RegistrationResult (interface)

Result of successful registration

**Signature**

```ts
export interface RegistrationResult {
  /** The newly created credential */
  credential: WebAuthnCredential;
  /** Whether the authenticator was verified */
  verified: boolean;
}
```

## WebAuthnChallenge (interface)

Represents a WebAuthn challenge used during registration and authentication

**Signature**

```ts
export interface WebAuthnChallenge {
  /** Challenge bytes (random value) */
  challenge: Uint8Array;
  /** Expiration timestamp */
  expiresAt: number;
  /** User ID associated with the challenge (optional, used for authentication) */
  userId?: string;
}
```

## WebAuthnConfig (interface)

Configuration for WebAuthn service

**Signature**

```ts
export interface WebAuthnConfig {
  /** Relying party ID (typically your domain) */
  relyingPartyId: string;
  /** Relying party name */
  relyingPartyName: string;
  /** Expected origin(s) for WebAuthn requests */
  expectedOrigin: string | readonly string[];
  /** Challenge expiration time in milliseconds (default: 5 minutes) */
  challengeExpiresIn?: number;
}
```

## WebAuthnCredential (interface)

Represents a stored WebAuthn credential (passkey)

**Signature**

```ts
export interface WebAuthnCredential {
  /** Unique credential ID */
  id: string;
  /** User ID this credential belongs to */
  userId: string;
  /** Public key in COSE format */
  publicKey: Uint8Array;
  /** Algorithm used (COSE algorithm identifier) */
  algorithm: number;
  /** Counter value to prevent replay attacks */
  counter: number;
  /** When the credential was created */
  createdAt: number;
  /** Optional credential name/label */
  name?: string;
  /** Transports this credential supports */
  transports?: readonly string[];
}
```

## WebAuthnService

**Signature**

```ts
export declare const WebAuthnService: typeof WebAuthnServiceTag;
```

## WebAuthnService (interface)

WebAuthn service for managing passkey registration and authentication

**Signature**

```ts
export interface WebAuthnService {
  /** Generate a challenge for registration */
  generateRegistrationChallenge: (user: WebAuthnUser) => Effect.Effect<
    {
      challenge: Uint8Array;
      expiresAt: number;
    },
    Errors.AuthError
  >;

  /** Verify registration response from client */
  verifyRegistration: (
    challenge: Uint8Array,
    response: RegistrationResponse,
  ) => Effect.Effect<
    RegistrationResult,
    | Errors.WebAuthnVerificationError
    | Errors.ChallengeNotFoundError
    | Errors.ChallengeExpiredError
    | Errors.AuthError
  >;

  /** Generate a challenge for authentication */
  generateAuthenticationChallenge: (userId: string) => Effect.Effect<
    {
      challenge: Uint8Array;
      expiresAt: number;
    },
    Errors.AuthError
  >;

  /** Verify authentication response from client */
  verifyAuthentication: (
    challenge: Uint8Array,
    response: AuthenticationResponse,
  ) => Effect.Effect<
    AuthenticationResult,
    | Errors.WebAuthnVerificationError
    | Errors.CredentialNotFoundError
    | Errors.ChallengeNotFoundError
    | Errors.ChallengeExpiredError
    | Errors.AuthError
  >;
}
```

## WebAuthnServiceLayer

**Signature**

```ts
export declare const WebAuthnServiceLayer: (
  config: WebAuthnConfig,
) => Layer.Layer<WebAuthnServiceTag, never, ChallengeStoreTag | CredentialStoreTag>;
```

## WebAuthnServiceTag (class)

**Signature**

```ts
export declare class WebAuthnServiceTag
```

## WebAuthnUser (interface)

User information for WebAuthn registration

**Signature**

```ts
export interface WebAuthnUser {
  /** User ID */
  id: string;
  /** Username or email */
  name: string;
  /** Display name */
  displayName: string;
}
```

## base64UrlDecode

Helper to decode base64url to Uint8Array

**Signature**

```ts
export declare function base64UrlDecode(str: string): Uint8Array;
```

## makeWebAuthnService

Create a WebAuthn service

**Signature**

```ts
export declare const makeWebAuthnService: (
  config: WebAuthnConfig,
) => Effect.Effect<WebAuthnService, never, ChallengeStoreTag | CredentialStoreTag>;
```
