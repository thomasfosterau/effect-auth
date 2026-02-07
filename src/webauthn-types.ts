/**
 * WebAuthn types for passkey authentication
 * Following Copenhagen/Oslo guidelines for WebAuthn implementation
 */

/**
 * Represents a WebAuthn challenge used during registration and authentication
 */
export interface WebAuthnChallenge {
  /** Challenge bytes (random value) */
  challenge: Uint8Array
  /** Expiration timestamp */
  expiresAt: number
  /** User ID associated with the challenge (optional, used for authentication) */
  userId?: string
}

/**
 * Represents a stored WebAuthn credential (passkey)
 */
export interface WebAuthnCredential {
  /** Unique credential ID */
  id: string
  /** User ID this credential belongs to */
  userId: string
  /** Public key in COSE format */
  publicKey: Uint8Array
  /** Algorithm used (COSE algorithm identifier) */
  algorithm: number
  /** Counter value to prevent replay attacks */
  counter: number
  /** When the credential was created */
  createdAt: number
  /** Optional credential name/label */
  name?: string
  /** Transports this credential supports */
  transports?: readonly string[]
}

/**
 * Configuration for WebAuthn service
 */
export interface WebAuthnConfig {
  /** Relying party ID (typically your domain) */
  relyingPartyId: string
  /** Relying party name */
  relyingPartyName: string
  /** Expected origin(s) for WebAuthn requests */
  expectedOrigin: string | readonly string[]
  /** Challenge expiration time in milliseconds (default: 5 minutes) */
  challengeExpiresIn?: number
}

/**
 * User information for WebAuthn registration
 */
export interface WebAuthnUser {
  /** User ID */
  id: string
  /** Username or email */
  name: string
  /** Display name */
  displayName: string
}

/**
 * Registration response from client
 */
export interface RegistrationResponse {
  /** Credential ID */
  credentialId: Uint8Array
  /** Attestation object from client */
  attestationObject: Uint8Array
  /** Client data JSON from client */
  clientDataJSON: Uint8Array
}

/**
 * Authentication response from client
 */
export interface AuthenticationResponse {
  /** Credential ID */
  credentialId: Uint8Array
  /** Authenticator data from client */
  authenticatorData: Uint8Array
  /** Client data JSON from client */
  clientDataJSON: Uint8Array
  /** Signature from authenticator */
  signature: Uint8Array
}

/**
 * Result of successful registration
 */
export interface RegistrationResult {
  /** The newly created credential */
  credential: WebAuthnCredential
  /** Whether the authenticator was verified */
  verified: boolean
}

/**
 * Result of successful authentication
 */
export interface AuthenticationResult {
  /** The credential used for authentication */
  credential: WebAuthnCredential
  /** Updated counter value */
  newCounter: number
}
