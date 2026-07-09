/**
 * WebAuthn types for passkey authentication
 * Following Copenhagen/Oslo guidelines for WebAuthn implementation
 */

/**
 * Represents a WebAuthn challenge used during registration and authentication
 */
export interface WebAuthnChallenge {
  /** Challenge bytes (random value) */
  challenge: Uint8Array;
  /** Expiration timestamp */
  expiresAt: number;
  /** User ID associated with the challenge (optional, used for authentication) */
  userId?: string;
}

/**
 * Represents a stored WebAuthn credential (passkey)
 */
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

/**
 * Configuration for WebAuthn service
 */
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

/** A `PublicKeyCredentialParameters` entry advertised to the authenticator. */
export interface PublicKeyCredentialParameter {
  readonly type: "public-key";
  readonly alg: number;
}

/** A credential the authenticator should exclude (registration) or allow. */
export interface PublicKeyCredentialDescriptor {
  readonly type: "public-key";
  /** Credential ID, base64url-encoded. */
  readonly id: string;
  readonly transports?: readonly string[];
}

/** Authenticator-selection criteria advertised during registration. */
export interface AuthenticatorSelectionCriteria {
  readonly residentKey?: "required" | "preferred" | "discouraged";
  readonly requireResidentKey?: boolean;
  readonly userVerification: "required" | "preferred" | "discouraged";
}

/**
 * Registration challenge plus the options a client passes to
 * `navigator.credentials.create()`.
 */
export interface RegistrationChallenge {
  readonly challenge: Uint8Array;
  readonly expiresAt: number;
  /** Algorithms the RP accepts, most-preferred first. */
  readonly pubKeyCredParams: readonly PublicKeyCredentialParameter[];
  /** The user's existing credentials, to prevent duplicate registration. */
  readonly excludeCredentials: readonly PublicKeyCredentialDescriptor[];
  readonly authenticatorSelection: AuthenticatorSelectionCriteria;
}

/**
 * User information for WebAuthn registration
 */
export interface WebAuthnUser {
  /** User ID */
  id: string;
  /** Username or email */
  name: string;
  /** Display name */
  displayName: string;
}

/**
 * Registration response from client
 */
export interface RegistrationResponse {
  /** Credential ID */
  credentialId: Uint8Array;
  /** Attestation object from client */
  attestationObject: Uint8Array;
  /** Client data JSON from client */
  clientDataJSON: Uint8Array;
}

/**
 * Authentication response from client
 */
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

/**
 * Result of successful registration
 */
export interface RegistrationResult {
  /** The newly created credential */
  credential: WebAuthnCredential;
  /** Whether the authenticator was verified */
  verified: boolean;
}

/**
 * Result of successful authentication
 */
export interface AuthenticationResult {
  /** The credential used for authentication */
  credential: WebAuthnCredential;
  /** Updated counter value */
  newCounter: number;
}

/**
 * WebAuthn service for passkey authentication
 * Following Oslo/Copenhagen guidelines for WebAuthn implementation
 */

import { Context, Effect } from "effect";
import { coseAlgorithmES256, coseAlgorithmRS256, coseAlgorithmEdDSA } from "@oslojs/webauthn";
import * as Errors from "./Errors.ts";

/**
 * COSE algorithm identifiers this service can register and verify:
 * ES256 (-7, ECDSA P-256), RS256 (-257, RSASSA-PKCS1-v1_5), and EdDSA (-8,
 * Ed25519). Advertised to authenticators via `pubKeyCredParams`.
 */
export const SUPPORTED_COSE_ALGORITHMS = [
  coseAlgorithmES256,
  coseAlgorithmRS256,
  coseAlgorithmEdDSA,
] as const;

/**
 * WebAuthn challenge store interface
 * Implement this to store challenges in your database
 */
export interface ChallengeStoreShape {
  /** Store a challenge */
  create: (challenge: WebAuthnChallenge) => Effect.Effect<WebAuthnChallenge, Errors.AuthError>;
  /** Get a challenge by its value, or `null` when no such challenge exists. */
  get: (challenge: Uint8Array) => Effect.Effect<WebAuthnChallenge | null, Errors.AuthError>;
  /** Delete a challenge */
  delete: (challenge: Uint8Array) => Effect.Effect<void, Errors.AuthError>;
}

/**
 * WebAuthn credential store interface
 * Implement this to store credentials in your database
 */
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

/**
 * Context tag for ChallengeStore
 */
export class ChallengeStore extends Context.Service<ChallengeStore, ChallengeStoreShape>()(
  "@effect-auth/ChallengeStore",
) {}

/**
 * Context tag for CredentialStore
 */
export class CredentialStore extends Context.Service<CredentialStore, CredentialStoreShape>()(
  "@effect-auth/CredentialStore",
) {}

/**
 * Helper to decode base64url to Uint8Array
 */
export function base64UrlDecode(str: string): Uint8Array {
  // Convert base64url to base64
  let base64 = str.replace(/-/g, "+").replace(/_/g, "/");
  // Add padding if needed
  while (base64.length % 4 !== 0) {
    base64 += "=";
  }
  return new Uint8Array(Buffer.from(base64, "base64"));
}
