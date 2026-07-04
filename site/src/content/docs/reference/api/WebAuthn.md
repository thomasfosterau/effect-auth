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
  - [AuthenticatorSelectionCriteria (interface)](#authenticatorselectioncriteria-interface)
  - [ChallengeStore (class)](#challengestore-class)
  - [ChallengeStoreShape (interface)](#challengestoreshape-interface)
  - [CredentialStore (class)](#credentialstore-class)
  - [CredentialStoreShape (interface)](#credentialstoreshape-interface)
  - [PublicKeyCredentialDescriptor (interface)](#publickeycredentialdescriptor-interface)
  - [PublicKeyCredentialParameter (interface)](#publickeycredentialparameter-interface)
  - [RegistrationChallenge (interface)](#registrationchallenge-interface)
  - [RegistrationResponse (interface)](#registrationresponse-interface)
  - [RegistrationResult (interface)](#registrationresult-interface)
  - [SUPPORTED_COSE_ALGORITHMS](#supported_cose_algorithms)
  - [WebAuthnChallenge (interface)](#webauthnchallenge-interface)
  - [WebAuthnConfig (interface)](#webauthnconfig-interface)
  - [WebAuthnCredential (interface)](#webauthncredential-interface)
  - [WebAuthnService (class)](#webauthnservice-class)
  - [WebAuthnServiceShape (interface)](#webauthnserviceshape-interface)
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

## AuthenticatorSelectionCriteria (interface)

Authenticator-selection criteria advertised during registration.

**Signature**

```ts
export interface AuthenticatorSelectionCriteria {
  readonly residentKey?: "required" | "preferred" | "discouraged";
  readonly requireResidentKey?: boolean;
  readonly userVerification: "required" | "preferred" | "discouraged";
}
```

## ChallengeStore (class)

Context tag for ChallengeStore

**Signature**

```ts
export declare class ChallengeStore
```

## ChallengeStoreShape (interface)

WebAuthn challenge store interface
Implement this to store challenges in your database

**Signature**

```ts
export interface ChallengeStoreShape {
  /** Store a challenge */
  create: (challenge: WebAuthnChallenge) => Effect.Effect<WebAuthnChallenge, Errors.AuthError>;
  /** Get a challenge by its value, or `null` when no such challenge exists. */
  get: (challenge: Uint8Array) => Effect.Effect<WebAuthnChallenge | null, Errors.AuthError>;
  /** Delete a challenge */
  delete: (challenge: Uint8Array) => Effect.Effect<void, Errors.AuthError>;
}
```

## CredentialStore (class)

Context tag for CredentialStore

**Signature**

```ts
export declare class CredentialStore
```

## CredentialStoreShape (interface)

WebAuthn credential store interface
Implement this to store credentials in your database

**Signature**

```ts
export interface CredentialStoreShape {
  /** Store a credential */
  create: (credential: WebAuthnCredential) => Effect.Effect<WebAuthnCredential, Errors.AuthError>;
  /** Get a credential by ID, or `null` when no such credential exists. */
  get: (credentialId: string) => Effect.Effect<WebAuthnCredential | null, Errors.AuthError>;
  /** Update a credential (e.g., counter) */
  update: (credential: WebAuthnCredential) => Effect.Effect<WebAuthnCredential, Errors.AuthError>;
  /** Delete a credential */
  delete: (credentialId: string) => Effect.Effect<void, Errors.AuthError>;
  /** List all credentials for a user */
  listByUserId: (userId: string) => Effect.Effect<readonly WebAuthnCredential[], Errors.AuthError>;
}
```

## PublicKeyCredentialDescriptor (interface)

A credential the authenticator should exclude (registration) or allow.

**Signature**

```ts
export interface PublicKeyCredentialDescriptor {
  readonly type: "public-key";
  /** Credential ID, base64url-encoded. */
  readonly id: string;
  readonly transports?: readonly string[];
}
```

## PublicKeyCredentialParameter (interface)

A `PublicKeyCredentialParameters` entry advertised to the authenticator.

**Signature**

```ts
export interface PublicKeyCredentialParameter {
  readonly type: "public-key";
  readonly alg: number;
}
```

## RegistrationChallenge (interface)

Registration challenge plus the options a client passes to
`navigator.credentials.create()`.

**Signature**

```ts
export interface RegistrationChallenge {
  readonly challenge: Uint8Array;
  readonly expiresAt: number;
  /** Algorithms the RP accepts, most-preferred first. */
  readonly pubKeyCredParams: readonly PublicKeyCredentialParameter[];
  /** The user's existing credentials, to prevent duplicate registration. */
  readonly excludeCredentials: readonly PublicKeyCredentialDescriptor[];
  readonly authenticatorSelection: AuthenticatorSelectionCriteria;
}
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

## SUPPORTED_COSE_ALGORITHMS

COSE algorithm identifiers this service can register and verify:
ES256 (-7, ECDSA P-256), RS256 (-257, RSASSA-PKCS1-v1_5), and EdDSA (-8,
Ed25519). Advertised to authenticators via `pubKeyCredParams`.

**Signature**

```ts
export declare const SUPPORTED_COSE_ALGORITHMS: readonly [-7, -257, -8];
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
  /**
   * Discoverable-credential (passkey) requirement advertised during
   * registration. `"required"` requests a resident key; omit to leave it to
   * the authenticator.
   */
  residentKey?: "required" | "preferred" | "discouraged";
  /** User-verification requirement (default `"preferred"`). */
  userVerification?: "required" | "preferred" | "discouraged";
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

## WebAuthnService (class)

**Signature**

```ts
export declare class WebAuthnService
```

## WebAuthnServiceShape (interface)

WebAuthn service for managing passkey registration and authentication

**Signature**

```ts
export interface WebAuthnServiceShape {
  /** Generate a challenge for registration */
  generateRegistrationChallenge: (
    user: WebAuthnUser,
  ) => Effect.Effect<RegistrationChallenge, Errors.AuthError>;

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
) => Effect.Effect<WebAuthnServiceShape, never, ChallengeStore | CredentialStore>;
```
