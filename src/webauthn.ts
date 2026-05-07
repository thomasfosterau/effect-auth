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

/**
 * WebAuthn service for passkey authentication
 * Following Oslo/Copenhagen guidelines for WebAuthn implementation
 */

import { Context, Effect, Layer } from "effect"
import {
  parseAttestationObject,
  parseClientDataJSON,
  parseAuthenticatorData,
  coseAlgorithmES256,
  ClientDataType,
  type ClientData,
  type AuthenticatorData
} from "@oslojs/webauthn"
import * as crypto from "node:crypto"
import * as Errors from "./Errors.js"

/**
 * WebAuthn challenge store interface
 * Implement this to store challenges in your database
 */
export interface ChallengeStore {
  /** Store a challenge */
  create: (challenge: WebAuthnChallenge) => Effect.Effect<WebAuthnChallenge, Errors.AuthError>
  /** Get a challenge by its value */
  get: (challenge: Uint8Array) => Effect.Effect<WebAuthnChallenge, Errors.ChallengeNotFoundError>
  /** Delete a challenge */
  delete: (challenge: Uint8Array) => Effect.Effect<void, Errors.AuthError>
}

/**
 * WebAuthn credential store interface
 * Implement this to store credentials in your database
 */
export interface CredentialStore {
  /** Store a credential */
  create: (credential: WebAuthnCredential) => Effect.Effect<WebAuthnCredential, Errors.AuthError>
  /** Get a credential by ID */
  get: (credentialId: string) => Effect.Effect<WebAuthnCredential, Errors.CredentialNotFoundError>
  /** Update a credential (e.g., counter) */
  update: (credential: WebAuthnCredential) => Effect.Effect<WebAuthnCredential, Errors.AuthError>
  /** Delete a credential */
  delete: (credentialId: string) => Effect.Effect<void, Errors.AuthError>
  /** Get all credentials for a user */
  getByUserId: (userId: string) => Effect.Effect<readonly WebAuthnCredential[], Errors.AuthError>
}

/**
 * Context tag for ChallengeStore
 */
export class ChallengeStoreTag extends Context.Tag("@effect-auth/ChallengeStore")<
  ChallengeStoreTag,
  ChallengeStore
>() { }

// Public ergonomic alias
export const ChallengeStore = ChallengeStoreTag

/**
 * Context tag for CredentialStore
 */
export class CredentialStoreTag extends Context.Tag("@effect-auth/CredentialStore")<
  CredentialStoreTag,
  CredentialStore
>() { }

// Public ergonomic alias
export const CredentialStore = CredentialStoreTag

/**
 * WebAuthn service for managing passkey registration and authentication
 */
export interface WebAuthnService {
  /** Generate a challenge for registration */
  generateRegistrationChallenge: (user: WebAuthnUser) => Effect.Effect<{
    challenge: Uint8Array
    expiresAt: number
  }, Errors.AuthError>

  /** Verify registration response from client */
  verifyRegistration: (
    challenge: Uint8Array,
    response: RegistrationResponse
  ) => Effect.Effect<RegistrationResult, Errors.WebAuthnVerificationError | Errors.ChallengeNotFoundError | Errors.ChallengeExpiredError | Errors.AuthError>

  /** Generate a challenge for authentication */
  generateAuthenticationChallenge: (userId: string) => Effect.Effect<{
    challenge: Uint8Array
    expiresAt: number
  }, Errors.AuthError>

  /** Verify authentication response from client */
  verifyAuthentication: (
    challenge: Uint8Array,
    response: AuthenticationResponse
  ) => Effect.Effect<AuthenticationResult, Errors.WebAuthnVerificationError | Errors.CredentialNotFoundError | Errors.ChallengeNotFoundError | Errors.ChallengeExpiredError | Errors.AuthError>
}

export class WebAuthnServiceTag extends Context.Tag("@effect-auth/WebAuthnService")<
  WebAuthnServiceTag,
  WebAuthnService
>() { }

// Public ergonomic alias
export const WebAuthnService = WebAuthnServiceTag

/**
 * Create a WebAuthn service
 */
export const makeWebAuthnService = (
  config: WebAuthnConfig
): Effect.Effect<WebAuthnService, never, ChallengeStoreTag | CredentialStoreTag> =>
  Effect.gen(function* () {
    const challengeStore = yield* ChallengeStoreTag
    const credentialStore = yield* CredentialStoreTag

    const challengeExpiresIn = config.challengeExpiresIn ?? 5 * 60 * 1000 // 5 minutes default

    return {
      generateRegistrationChallenge: (user: WebAuthnUser) =>
        Effect.gen(function* () {
          // Generate random challenge (32 bytes = 256 bits)
          const challenge = crypto.randomBytes(32)
          const expiresAt = Date.now() + challengeExpiresIn

          const challengeData: WebAuthnChallenge = {
            challenge,
            expiresAt,
            userId: user.id
          }

          yield* challengeStore.create(challengeData)

          return { challenge, expiresAt }
        }),

      verifyRegistration: (challenge: Uint8Array, response: RegistrationResponse) =>
        Effect.gen(function* () {
          // Get and verify challenge
          const storedChallenge = yield* challengeStore.get(challenge)

          if (Date.now() > storedChallenge.expiresAt) {
            yield* challengeStore.delete(challenge)
            return yield* Effect.fail(
              new Errors.ChallengeExpiredError({
                message: "Challenge has expired"
              })
            )
          }

          // Parse client data JSON
          let clientData: ClientData
          try {
            clientData = parseClientDataJSON(response.clientDataJSON)
          } catch (error) {
            return yield* Effect.fail(
              new Errors.WebAuthnVerificationError({
                message: "Failed to parse client data JSON",
                cause: error
              })
            )
          }

          // Verify challenge matches
          if (!compareUint8Arrays(clientData.challenge, challenge)) {
            return yield* Effect.fail(
              new Errors.WebAuthnVerificationError({
                message: "Challenge mismatch"
              })
            )
          }

          // Verify origin
          const origins = Array.isArray(config.expectedOrigin)
            ? config.expectedOrigin
            : [config.expectedOrigin]

          if (!origins.includes(clientData.origin)) {
            return yield* Effect.fail(
              new Errors.WebAuthnVerificationError({
                message: `Invalid origin: ${clientData.origin}`
              })
            )
          }

          // Verify type
          if (clientData.type !== ClientDataType.Create) {
            return yield* Effect.fail(
              new Errors.WebAuthnVerificationError({
                message: `Invalid type: ${clientData.type}`
              })
            )
          }

          // Parse attestation object
          let authenticatorData: AuthenticatorData
          try {
            const parsed = parseAttestationObject(response.attestationObject)
            authenticatorData = parsed.authenticatorData
          } catch (error) {
            return yield* Effect.fail(
              new Errors.WebAuthnVerificationError({
                message: "Failed to parse attestation object",
                cause: error
              })
            )
          }

          // Verify authenticator data
          if (!authenticatorData.userPresent) {
            return yield* Effect.fail(
              new Errors.WebAuthnVerificationError({
                message: "User not present"
              })
            )
          }

          // Verify relying party ID hash
          if (!authenticatorData.verifyRelyingPartyIdHash(config.relyingPartyId)) {
            return yield* Effect.fail(
              new Errors.WebAuthnVerificationError({
                message: "Invalid relying party ID hash"
              })
            )
          }

          // Extract credential
          if (!authenticatorData.credential) {
            return yield* Effect.fail(
              new Errors.WebAuthnVerificationError({
                message: "No credential in authenticator data"
              })
            )
          }

          // Verify algorithm - only ES256 is currently supported
          const publicKey = authenticatorData.credential.publicKey
          const algorithm = publicKey.algorithm()

          // Support ES256 only for now
          if (algorithm !== coseAlgorithmES256) {
            return yield* Effect.fail(
              new Errors.WebAuthnVerificationError({
                message: `Unsupported algorithm: ${algorithm}. Only ES256 is currently supported.`
              })
            )
          }

          // Encode credential ID as base64url for storage
          const credentialId = base64UrlEncode(response.credentialId)

          // Serialize public key for storage
          const publicKeyBytes = serializePublicKey(publicKey, algorithm)

          // Validate userId is present
          if (!storedChallenge.userId) {
            return yield* Effect.fail(
              new Errors.WebAuthnVerificationError({
                message: "Challenge missing user ID"
              })
            )
          }

          // Create credential object
          const credential: WebAuthnCredential = {
            id: credentialId,
            userId: storedChallenge.userId,
            publicKey: publicKeyBytes,
            algorithm,
            counter: authenticatorData.signatureCounter,
            createdAt: Date.now()
          }

          // Store credential
          yield* credentialStore.create(credential)

          // Delete used challenge
          yield* challengeStore.delete(challenge)

          return {
            credential,
            verified: authenticatorData.userVerified
          }
        }),

      generateAuthenticationChallenge: (userId: string) =>
        Effect.gen(function* () {
          const challenge = crypto.randomBytes(32)
          const expiresAt = Date.now() + challengeExpiresIn

          const challengeData: WebAuthnChallenge = {
            challenge,
            expiresAt,
            userId
          }

          yield* challengeStore.create(challengeData)

          return { challenge, expiresAt }
        }),

      verifyAuthentication: (challenge: Uint8Array, response: AuthenticationResponse) =>
        Effect.gen(function* () {
          // Get and verify challenge
          const storedChallenge = yield* challengeStore.get(challenge)

          if (Date.now() > storedChallenge.expiresAt) {
            yield* challengeStore.delete(challenge)
            return yield* Effect.fail(
              new Errors.ChallengeExpiredError({
                message: "Challenge has expired"
              })
            )
          }

          // Get credential
          const credentialId = base64UrlEncode(response.credentialId)
          const credential = yield* credentialStore.get(credentialId)

          // Parse client data JSON
          let clientData: ClientData
          try {
            clientData = parseClientDataJSON(response.clientDataJSON)
          } catch (error) {
            return yield* Effect.fail(
              new Errors.WebAuthnVerificationError({
                message: "Failed to parse client data JSON",
                cause: error
              })
            )
          }

          // Verify challenge matches
          if (!compareUint8Arrays(clientData.challenge, challenge)) {
            return yield* Effect.fail(
              new Errors.WebAuthnVerificationError({
                message: "Challenge mismatch"
              })
            )
          }

          // Verify origin
          const origins = Array.isArray(config.expectedOrigin)
            ? config.expectedOrigin
            : [config.expectedOrigin]

          if (!origins.includes(clientData.origin)) {
            return yield* Effect.fail(
              new Errors.WebAuthnVerificationError({
                message: `Invalid origin: ${clientData.origin}`
              })
            )
          }

          // Verify type
          if (clientData.type !== ClientDataType.Get) {
            return yield* Effect.fail(
              new Errors.WebAuthnVerificationError({
                message: `Invalid type: ${clientData.type}`
              })
            )
          }

          // Parse authenticator data
          let authenticatorData: AuthenticatorData
          try {
            authenticatorData = parseAuthenticatorData(response.authenticatorData)
          } catch (error) {
            return yield* Effect.fail(
              new Errors.WebAuthnVerificationError({
                message: "Failed to parse authenticator data",
                cause: error
              })
            )
          }

          // Verify user presence
          if (!authenticatorData.userPresent) {
            return yield* Effect.fail(
              new Errors.WebAuthnVerificationError({
                message: "User not present"
              })
            )
          }

          // Verify relying party ID hash
          if (!authenticatorData.verifyRelyingPartyIdHash(config.relyingPartyId)) {
            return yield* Effect.fail(
              new Errors.WebAuthnVerificationError({
                message: "Invalid relying party ID hash"
              })
            )
          }

          // Verify counter (anti-replay protection)
          // If both counters are 0, the authenticator does not support counter-based replay protection
          // and the counter check must be skipped per WebAuthn specification.
          if (!(authenticatorData.signatureCounter === 0 && credential.counter === 0)) {
            if (authenticatorData.signatureCounter <= credential.counter) {
              return yield* Effect.fail(
                new Errors.WebAuthnVerificationError({
                  message: "Invalid counter value (possible cloned authenticator)"
                })
              )
            }
          }

          // Verify signature
          const verified = yield* verifySignature(
            credential.publicKey,
            credential.algorithm,
            response.authenticatorData,
            response.clientDataJSON,
            response.signature
          )

          if (!verified) {
            return yield* Effect.fail(
              new Errors.WebAuthnVerificationError({
                message: "Invalid signature"
              })
            )
          }

          // Update credential counter
          const updatedCredential = {
            ...credential,
            counter: authenticatorData.signatureCounter
          }
          yield* credentialStore.update(updatedCredential)

          // Delete used challenge
          yield* challengeStore.delete(challenge)

          return {
            credential: updatedCredential,
            newCounter: authenticatorData.signatureCounter
          }
        })
    }
  })

export const WebAuthnServiceLayer = (config: WebAuthnConfig) =>
  Layer.effect(WebAuthnServiceTag, makeWebAuthnService(config))

/**
 * Helper to serialize public key for storage
 */
function serializePublicKey(publicKey: any, algorithm: number): Uint8Array {
  if (algorithm === coseAlgorithmES256) {
    // ES256 - extract EC2 key
    const ec2Key = publicKey.ec2()
    // Convert bigints to bytes (32 bytes each for P-256)
    const xBytes = bigintToBytes(ec2Key.x, 32)
    const yBytes = bigintToBytes(ec2Key.y, 32)
    // Concatenate: 0x04 (uncompressed) + x + y
    const result = new Uint8Array(65)
    result[0] = 0x04
    result.set(xBytes, 1)
    result.set(yBytes, 33)
    return result
  }
  throw new Error(`Unsupported algorithm: ${algorithm}`)
}

/**
 * Helper to convert bigint to bytes
 */
function bigintToBytes(value: bigint, minLength?: number): Uint8Array {
  const hex = value.toString(16)
  const paddedHex = hex.length % 2 === 0 ? hex : "0" + hex
  const finalHex = paddedHex.padStart(minLength ? minLength * 2 : 0, "0")
  const bytes = new Uint8Array(finalHex.length / 2)
  for (let i = 0; i < bytes.length; i++) {
    bytes[i] = parseInt(finalHex.substring(i * 2, i * 2 + 2), 16)
  }
  return bytes
}

/**
 * Helper function to verify signature
 */
function verifySignature(
  publicKeyBytes: Uint8Array,
  algorithm: number,
  authenticatorData: Uint8Array,
  clientDataJSON: Uint8Array,
  signature: Uint8Array
): Effect.Effect<boolean, Errors.WebAuthnVerificationError> {
  return Effect.gen(function* () {
    try {
      // Hash client data JSON
      const clientDataHash = crypto.createHash("sha256")
        .update(clientDataJSON)
        .digest()

      // Concatenate authenticator data and client data hash
      const signedData = new Uint8Array(authenticatorData.length + clientDataHash.length)
      signedData.set(authenticatorData, 0)
      signedData.set(clientDataHash, authenticatorData.length)

      // Import public key and verify signature
      const publicKey = yield* Effect.tryPromise({
        try: async () => {
          if (algorithm === coseAlgorithmES256) {
            // ES256 (ECDSA with P-256 and SHA-256)
            // publicKeyBytes format: 0x04 || x (32 bytes) || y (32 bytes)
            // Create a properly sized ArrayBuffer
            const keyBuffer = new ArrayBuffer(publicKeyBytes.length)
            const keyView = new Uint8Array(keyBuffer)
            keyView.set(publicKeyBytes)
            return await crypto.subtle.importKey(
              "raw",
              keyBuffer,
              { name: "ECDSA", namedCurve: "P-256" },
              false,
              ["verify"]
            )
          }
          throw new Error(`Unsupported algorithm: ${algorithm}`)
        },
        catch: (error) => new Errors.WebAuthnVerificationError({
          message: "Failed to import public key",
          cause: error
        })
      })

      const verified = yield* Effect.tryPromise({
        try: async () => {
          // Create properly sized ArrayBuffers
          const signatureBuffer = new ArrayBuffer(signature.length)
          const signatureView = new Uint8Array(signatureBuffer)
          signatureView.set(signature)

          const signedDataBuffer = new ArrayBuffer(signedData.length)
          const signedDataView = new Uint8Array(signedDataBuffer)
          signedDataView.set(signedData)

          if (algorithm === coseAlgorithmES256) {
            return await crypto.subtle.verify(
              { name: "ECDSA", hash: "SHA-256" },
              publicKey,
              signatureBuffer,
              signedDataBuffer
            )
          }
          throw new Error(`Unsupported algorithm: ${algorithm}`)
        },
        catch: (error) => new Errors.WebAuthnVerificationError({
          message: "Failed to verify signature",
          cause: error
        })
      })

      return verified
    } catch (error) {
      return yield* Effect.fail(
        new Errors.WebAuthnVerificationError({
          message: "Failed to verify signature",
          cause: error
        })
      )
    }
  })
}

/**
 * Helper to compare two Uint8Arrays using timing-safe comparison
 */
function compareUint8Arrays(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) {
    return false
  }
  const bufA = Buffer.from(a)
  const bufB = Buffer.from(b)
  return crypto.timingSafeEqual(bufA, bufB)
}

/**
 * Helper to encode Uint8Array to base64url
 */
function base64UrlEncode(buffer: Uint8Array): string {
  const base64 = Buffer.from(buffer).toString("base64")
  return base64
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=/g, "")
}

/**
 * Helper to decode base64url to Uint8Array
 */
export function base64UrlDecode(str: string): Uint8Array {
  // Convert base64url to base64
  let base64 = str.replace(/-/g, "+").replace(/_/g, "/")
  // Add padding if needed
  while (base64.length % 4 !== 0) {
    base64 += "="
  }
  return new Uint8Array(Buffer.from(base64, "base64"))
}
