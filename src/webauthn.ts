/**
 * WebAuthn service for passkey authentication
 * Following Oslo/Copenhagen guidelines for WebAuthn implementation
 */

import { Effect, Context } from "effect"
import { 
  parseAttestationObject,
  parseClientDataJSON,
  parseAuthenticatorData,
  coseAlgorithmES256,
  coseAlgorithmRS256,
  ClientDataType,
  type ClientData,
  type AuthenticatorData
} from "@oslojs/webauthn"
import * as crypto from "node:crypto"
import * as Errors from "./errors.js"
import type {
  WebAuthnChallenge,
  WebAuthnCredential,
  WebAuthnConfig,
  WebAuthnUser,
  RegistrationResponse,
  AuthenticationResponse,
  RegistrationResult,
  AuthenticationResult
} from "./webauthn-types.js"

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
export const ChallengeStore = Context.GenericTag<ChallengeStore>("ChallengeStore")

/**
 * Context tag for CredentialStore
 */
export const CredentialStore = Context.GenericTag<CredentialStore>("CredentialStore")

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
    response: RegistrationResponse,
    expectedOrigin: string
  ) => Effect.Effect<RegistrationResult, Errors.WebAuthnVerificationError | Errors.ChallengeNotFoundError | Errors.ChallengeExpiredError | Errors.AuthError>

  /** Generate a challenge for authentication */
  generateAuthenticationChallenge: (userId: string) => Effect.Effect<{
    challenge: Uint8Array
    expiresAt: number
  }, Errors.AuthError>

  /** Verify authentication response from client */
  verifyAuthentication: (
    challenge: Uint8Array,
    response: AuthenticationResponse,
    expectedOrigin: string
  ) => Effect.Effect<AuthenticationResult, Errors.WebAuthnVerificationError | Errors.CredentialNotFoundError | Errors.ChallengeNotFoundError | Errors.ChallengeExpiredError | Errors.AuthError>
}

/**
 * Create a WebAuthn service
 */
export const makeWebAuthnService = (
  config: WebAuthnConfig
): Effect.Effect<WebAuthnService, never, ChallengeStore | CredentialStore> =>
  Effect.gen(function* () {
    const challengeStore = yield* ChallengeStore
    const credentialStore = yield* CredentialStore

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

      verifyRegistration: (challenge: Uint8Array, response: RegistrationResponse, _expectedOrigin: string) =>
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

          // Verify algorithm
          const publicKey = authenticatorData.credential.publicKey
          const algorithm = publicKey.algorithm()

          // Support ES256 and RS256
          if (algorithm !== coseAlgorithmES256 && algorithm !== coseAlgorithmRS256) {
            return yield* Effect.fail(
              new Errors.WebAuthnVerificationError({
                message: `Unsupported algorithm: ${algorithm}`
              })
            )
          }

          // Encode credential ID as base64url for storage
          const credentialId = base64UrlEncode(response.credentialId)

          // Serialize public key for storage
          const publicKeyBytes = serializePublicKey(publicKey, algorithm)

          // Create credential object
          const credential: WebAuthnCredential = {
            id: credentialId,
            userId: storedChallenge.userId!,
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

      verifyAuthentication: (challenge: Uint8Array, response: AuthenticationResponse, _expectedOrigin: string) =>
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
          if (authenticatorData.signatureCounter <= credential.counter) {
            return yield* Effect.fail(
              new Errors.WebAuthnVerificationError({
                message: "Invalid counter value (possible cloned authenticator)"
              })
            )
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
  } else if (algorithm === coseAlgorithmRS256) {
    // RS256 - extract RSA key
    const rsaKey = publicKey.rsa()
    // For RSA, we'll store n and e as DER-encoded SPKI
    // This is a simplified approach - in production you'd want proper DER encoding
    const nBytes = bigintToBytes(rsaKey.n)
    const eBytes = bigintToBytes(rsaKey.e)
    // Simple concatenation for storage (in real use, proper SPKI encoding would be better)
    const result = new Uint8Array(4 + nBytes.length + eBytes.length)
    const view = new DataView(result.buffer)
    view.setUint16(0, nBytes.length)
    view.setUint16(2, eBytes.length)
    result.set(nBytes, 4)
    result.set(eBytes, 4 + nBytes.length)
    return result
  }
  throw new Error(`Unsupported algorithm: ${algorithm}`)
}

/**
 * Helper to convert bigint to bytes
 */
function bigintToBytes(value: bigint, minLength?: number): Uint8Array {
  const hex = value.toString(16).padStart(minLength ? minLength * 2 : 0, '0')
  const bytes = new Uint8Array(hex.length / 2)
  for (let i = 0; i < bytes.length; i++) {
    bytes[i] = parseInt(hex.substr(i * 2, 2), 16)
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
            // Create a proper ArrayBuffer copy
            const keyBuffer = Buffer.from(publicKeyBytes).buffer
            return await crypto.subtle.importKey(
              "raw",
              keyBuffer,
              { name: "ECDSA", namedCurve: "P-256" },
              false,
              ["verify"]
            )
          } else if (algorithm === coseAlgorithmRS256) {
            // RS256 - would need proper SPKI encoding
            // For now, this is simplified
            throw new Error("RS256 signature verification not yet fully implemented")
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
          const signatureBuffer = Buffer.from(signature).buffer
          const signedDataBuffer = Buffer.from(signedData).buffer
          
          if (algorithm === coseAlgorithmES256) {
            return await crypto.subtle.verify(
              { name: "ECDSA", hash: "SHA-256" },
              publicKey,
              signatureBuffer,
              signedDataBuffer
            )
          } else {
            return await crypto.subtle.verify(
              "RSASSA-PKCS1-v1_5",
              publicKey,
              signatureBuffer,
              signedDataBuffer
            )
          }
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
 * Helper to compare two Uint8Arrays
 */
function compareUint8Arrays(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false
  for (let i = 0; i < a.length; i++) {
    if (a[i] !== b[i]) return false
  }
  return true
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
