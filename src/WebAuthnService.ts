/**
 * WebAuthn service for managing passkey registration and authentication
 */

import { Context, Effect, Layer } from "effect";
import * as Obs from "./Observability.ts";
import {
  parseAttestationObject,
  parseClientDataJSON,
  parseAuthenticatorData,
  coseAlgorithmES256,
  coseAlgorithmRS256,
  coseAlgorithmEdDSA,
  COSEPublicKey,
  ClientDataType,
  type ClientData,
  type AuthenticatorData,
} from "@oslojs/webauthn";
import * as crypto from "node:crypto";
import * as Errors from "./Errors.ts";
import {
  ChallengeStore,
  CredentialStore,
  SUPPORTED_COSE_ALGORITHMS,
  type AuthenticationResponse,
  type AuthenticationResult,
  type AuthenticatorSelectionCriteria,
  type PublicKeyCredentialDescriptor,
  type PublicKeyCredentialParameter,
  type RegistrationChallenge,
  type RegistrationResponse,
  type RegistrationResult,
  type WebAuthnChallenge,
  type WebAuthnConfig,
  type WebAuthnCredential,
  type WebAuthnUser,
} from "./WebAuthn.ts";

/**
 * WebAuthn service for managing passkey registration and authentication
 */
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

  /**
   * Generate a challenge for authentication.
   * Pass `userId` for a bound challenge (known user); omit for a
   * discoverable/usernameless challenge.
   */
  generateAuthenticationChallenge: (userId?: string) => Effect.Effect<
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

  /** List all passkeys registered for a user */
  listCredentials: (
    userId: string,
  ) => Effect.Effect<readonly WebAuthnCredential[], Errors.AuthError>;

  /** Delete a passkey; fails if the credential does not belong to `userId` */
  deleteCredential: (
    userId: string,
    credentialId: string,
  ) => Effect.Effect<void, Errors.CredentialNotFoundError | Errors.AuthError>;

  /** Rename a passkey; fails if the credential does not belong to `userId` */
  renameCredential: (
    userId: string,
    credentialId: string,
    name: string,
  ) => Effect.Effect<WebAuthnCredential, Errors.CredentialNotFoundError | Errors.AuthError>;
}

export class WebAuthnService extends Context.Service<WebAuthnService, WebAuthnService>()(
  "@effect-auth/WebAuthnService",
) {
  static readonly layer = (config: WebAuthnConfig) => Layer.effect(WebAuthnService, make(config));
}

/**
 * Create a WebAuthn service
 */
export const make = (
  config: WebAuthnConfig,
): Effect.Effect<WebAuthnService, never, ChallengeStore | CredentialStore> =>
  Effect.gen(function* () {
    const challengeStore = yield* ChallengeStore;
    const credentialStore = yield* CredentialStore;

    const challengeExpiresIn = config.challengeExpiresIn ?? 5 * 60 * 1000; // 5 minutes default

    return {
      generateRegistrationChallenge: (user: WebAuthnUser) =>
        Effect.gen(function* () {
          // Generate random challenge (32 bytes = 256 bits)
          const challenge: Uint8Array = crypto.randomBytes(32);
          const expiresAt = Date.now() + challengeExpiresIn;

          const challengeData: WebAuthnChallenge = {
            challenge,
            expiresAt,
            userId: user.id,
          };

          yield* challengeStore.create(challengeData);

          // Exclude the user's existing credentials to prevent re-registering
          // the same authenticator.
          const existing = yield* credentialStore.listByUserId(user.id);
          const excludeCredentials = existing.map(
            (c): PublicKeyCredentialDescriptor => ({
              type: "public-key",
              id: c.id,
              ...(c.transports && { transports: c.transports }),
            }),
          );

          const authenticatorSelection: AuthenticatorSelectionCriteria = {
            ...(config.residentKey && {
              residentKey: config.residentKey,
              requireResidentKey: config.residentKey === "required",
            }),
            userVerification: config.userVerification ?? "preferred",
          };

          return {
            challenge,
            expiresAt,
            pubKeyCredParams: SUPPORTED_COSE_ALGORITHMS.map(
              (alg): PublicKeyCredentialParameter => ({ type: "public-key", alg }),
            ),
            excludeCredentials,
            authenticatorSelection,
          };
        }),

      verifyRegistration: (challenge: Uint8Array, response: RegistrationResponse) =>
        Effect.gen(function* () {
          // Get and verify challenge
          const storedChallenge = yield* challengeStore.get(challenge);
          if (storedChallenge === null) {
            return yield* new Errors.ChallengeNotFoundError({ message: "Challenge not found" });
          }

          if (Date.now() > storedChallenge.expiresAt) {
            yield* challengeStore.delete(challenge);
            return yield* Effect.fail(
              new Errors.ChallengeExpiredError({
                message: "Challenge has expired",
              }),
            );
          }

          // Parse client data JSON
          let clientData: ClientData;
          try {
            clientData = parseClientDataJSON(response.clientDataJSON);
          } catch (error) {
            return yield* Effect.fail(
              new Errors.WebAuthnVerificationError({
                message: "Failed to parse client data JSON",
                cause: error,
              }),
            );
          }

          // Verify challenge matches
          if (!compareUint8Arrays(clientData.challenge, challenge)) {
            return yield* Effect.fail(
              new Errors.WebAuthnVerificationError({
                message: "Challenge mismatch",
              }),
            );
          }

          // Verify origin
          const origins = Array.isArray(config.expectedOrigin)
            ? config.expectedOrigin
            : [config.expectedOrigin];

          if (!origins.includes(clientData.origin)) {
            return yield* Effect.fail(
              new Errors.WebAuthnVerificationError({
                message: `Invalid origin: ${clientData.origin}`,
              }),
            );
          }

          // Verify type
          if (clientData.type !== ClientDataType.Create) {
            return yield* Effect.fail(
              new Errors.WebAuthnVerificationError({
                message: `Invalid type: ${clientData.type}`,
              }),
            );
          }

          // Parse attestation object
          let authenticatorData: AuthenticatorData;
          try {
            const parsed = parseAttestationObject(response.attestationObject);
            authenticatorData = parsed.authenticatorData;
          } catch (error) {
            return yield* Effect.fail(
              new Errors.WebAuthnVerificationError({
                message: "Failed to parse attestation object",
                cause: error,
              }),
            );
          }

          // Verify authenticator data
          if (!authenticatorData.userPresent) {
            return yield* Effect.fail(
              new Errors.WebAuthnVerificationError({
                message: "User not present",
              }),
            );
          }

          // Verify relying party ID hash
          if (!authenticatorData.verifyRelyingPartyIdHash(config.relyingPartyId)) {
            return yield* Effect.fail(
              new Errors.WebAuthnVerificationError({
                message: "Invalid relying party ID hash",
              }),
            );
          }

          // Extract credential
          if (!authenticatorData.credential) {
            return yield* Effect.fail(
              new Errors.WebAuthnVerificationError({
                message: "No credential in authenticator data",
              }),
            );
          }

          // Verify algorithm — ES256, RS256, and EdDSA are supported.
          const publicKey = authenticatorData.credential.publicKey;
          const algorithm = publicKey.algorithm();

          if (!(SUPPORTED_COSE_ALGORITHMS as readonly number[]).includes(algorithm)) {
            return yield* Effect.fail(
              new Errors.WebAuthnVerificationError({
                message: `Unsupported algorithm: ${algorithm}. Supported: ES256 (-7), RS256 (-257), EdDSA (-8).`,
              }),
            );
          }

          // Encode credential ID as base64url for storage
          const credentialId = base64UrlEncode(response.credentialId);

          // Serialize public key for storage
          const publicKeyBytes = serializePublicKey(publicKey, algorithm);

          // Validate userId is present
          if (!storedChallenge.userId) {
            return yield* Effect.fail(
              new Errors.WebAuthnVerificationError({
                message: "Challenge missing user ID",
              }),
            );
          }

          // Create credential object
          const credential: WebAuthnCredential = {
            id: credentialId,
            userId: storedChallenge.userId,
            publicKey: publicKeyBytes,
            algorithm,
            counter: authenticatorData.signatureCounter,
            createdAt: Date.now(),
          };

          // Store credential
          yield* credentialStore.create(credential);

          // Delete used challenge
          yield* challengeStore.delete(challenge);

          return {
            credential,
            verified: authenticatorData.userVerified,
          };
        }).pipe(
          Effect.withSpan("effect-auth.webauthn.register"),
          Effect.tap(() => Obs.recordWebAuthnRegistration("success")),
          Effect.tapError(() => Obs.recordWebAuthnRegistration("failure")),
        ),

      generateAuthenticationChallenge: (userId?: string) =>
        Effect.gen(function* () {
          const challenge: Uint8Array = crypto.randomBytes(32);
          const expiresAt = Date.now() + challengeExpiresIn;

          const challengeData: WebAuthnChallenge = {
            challenge,
            expiresAt,
            ...(userId !== undefined ? { userId } : {}),
          };

          yield* challengeStore.create(challengeData);

          return { challenge, expiresAt };
        }),

      verifyAuthentication: (challenge: Uint8Array, response: AuthenticationResponse) =>
        Effect.gen(function* () {
          // Get and verify challenge
          const storedChallenge = yield* challengeStore.get(challenge);
          if (storedChallenge === null) {
            return yield* Effect.fail(
              new Errors.ChallengeNotFoundError({ message: "Challenge not found" }),
            );
          }

          if (Date.now() > storedChallenge.expiresAt) {
            yield* challengeStore.delete(challenge);
            return yield* Effect.fail(
              new Errors.ChallengeExpiredError({
                message: "Challenge has expired",
              }),
            );
          }

          // Get credential — on the usernameless path the credentialId is the
          // lookup key; on the bound path we use the same route for consistency.
          const credentialId = base64UrlEncode(response.credentialId);
          const credential = yield* credentialStore.get(credentialId);
          if (credential === null) {
            return yield* Effect.fail(
              new Errors.CredentialNotFoundError({
                message: "Credential not found",
                credentialId,
              }),
            );
          }

          // Bound challenge: verify the credential belongs to the expected user.
          if (
            storedChallenge.userId !== undefined &&
            credential.userId !== storedChallenge.userId
          ) {
            return yield* Effect.fail(
              new Errors.WebAuthnVerificationError({
                message: "Credential does not belong to the expected user",
              }),
            );
          }

          // Parse client data JSON
          let clientData: ClientData;
          try {
            clientData = parseClientDataJSON(response.clientDataJSON);
          } catch (error) {
            return yield* Effect.fail(
              new Errors.WebAuthnVerificationError({
                message: "Failed to parse client data JSON",
                cause: error,
              }),
            );
          }

          // Verify challenge matches
          if (!compareUint8Arrays(clientData.challenge, challenge)) {
            return yield* Effect.fail(
              new Errors.WebAuthnVerificationError({
                message: "Challenge mismatch",
              }),
            );
          }

          // Verify origin
          const origins = Array.isArray(config.expectedOrigin)
            ? config.expectedOrigin
            : [config.expectedOrigin];

          if (!origins.includes(clientData.origin)) {
            return yield* Effect.fail(
              new Errors.WebAuthnVerificationError({
                message: `Invalid origin: ${clientData.origin}`,
              }),
            );
          }

          // Verify type
          if (clientData.type !== ClientDataType.Get) {
            return yield* Effect.fail(
              new Errors.WebAuthnVerificationError({
                message: `Invalid type: ${clientData.type}`,
              }),
            );
          }

          // Parse authenticator data
          let authenticatorData: AuthenticatorData;
          try {
            authenticatorData = parseAuthenticatorData(response.authenticatorData);
          } catch (error) {
            return yield* Effect.fail(
              new Errors.WebAuthnVerificationError({
                message: "Failed to parse authenticator data",
                cause: error,
              }),
            );
          }

          // Verify user presence
          if (!authenticatorData.userPresent) {
            return yield* Effect.fail(
              new Errors.WebAuthnVerificationError({
                message: "User not present",
              }),
            );
          }

          // Verify relying party ID hash
          if (!authenticatorData.verifyRelyingPartyIdHash(config.relyingPartyId)) {
            return yield* Effect.fail(
              new Errors.WebAuthnVerificationError({
                message: "Invalid relying party ID hash",
              }),
            );
          }

          // Verify counter (anti-replay protection)
          // If both counters are 0, the authenticator does not support counter-based replay protection
          // and the counter check must be skipped per WebAuthn specification.
          if (!(authenticatorData.signatureCounter === 0 && credential.counter === 0)) {
            if (authenticatorData.signatureCounter <= credential.counter) {
              return yield* Effect.fail(
                new Errors.WebAuthnVerificationError({
                  message: "Invalid counter value (possible cloned authenticator)",
                }),
              );
            }
          }

          // Verify signature
          const verified = yield* verifySignature(
            credential.publicKey,
            credential.algorithm,
            response.authenticatorData,
            response.clientDataJSON,
            response.signature,
          );

          if (!verified) {
            return yield* Effect.fail(
              new Errors.WebAuthnVerificationError({
                message: "Invalid signature",
              }),
            );
          }

          // Update credential counter
          const updatedCredential = {
            ...credential,
            counter: authenticatorData.signatureCounter,
          };
          yield* credentialStore.update(updatedCredential);

          // Delete used challenge
          yield* challengeStore.delete(challenge);

          return {
            credential: updatedCredential,
            newCounter: authenticatorData.signatureCounter,
          };
        }).pipe(
          Effect.withSpan("effect-auth.webauthn.authenticate"),
          Effect.tap(() => Obs.recordWebAuthnAuthentication("success")),
          Effect.tapError(() => Obs.recordWebAuthnAuthentication("failure")),
        ),

      listCredentials: (userId: string) => credentialStore.listByUserId(userId),

      deleteCredential: (userId: string, credentialId: string) =>
        Effect.gen(function* () {
          const credential = yield* credentialStore.get(credentialId);
          if (credential === null) {
            return yield* Effect.fail(
              new Errors.CredentialNotFoundError({ message: "Credential not found", credentialId }),
            );
          }
          if (credential.userId !== userId) {
            return yield* Effect.fail(
              new Errors.AuthError({ message: "Not authorized to delete this credential" }),
            );
          }
          yield* credentialStore.delete(credentialId);
        }),

      renameCredential: (userId: string, credentialId: string, name: string) =>
        Effect.gen(function* () {
          const credential = yield* credentialStore.get(credentialId);
          if (credential === null) {
            return yield* Effect.fail(
              new Errors.CredentialNotFoundError({ message: "Credential not found", credentialId }),
            );
          }
          if (credential.userId !== userId) {
            return yield* Effect.fail(
              new Errors.AuthError({ message: "Not authorized to rename this credential" }),
            );
          }
          return yield* credentialStore.update({ ...credential, name });
        }),
    };
  });

export class WebAuthnService extends Context.Service<WebAuthnService, WebAuthnServiceShape>()(
  "@effect-auth/WebAuthnService",
) {
  static readonly layer = (config: WebAuthnConfig) => Layer.effect(WebAuthnService, make(config));
}

const b64url = (bytes: Uint8Array): string => Buffer.from(bytes).toString("base64url");

/**
 * Serialize a COSE public key to SPKI DER for storage. Using a single
 * key-independent encoding (rather than a raw EC point) lets ES256, RS256, and
 * EdDSA credentials share one storage format and one verification path.
 */
function serializePublicKey(publicKey: COSEPublicKey, algorithm: number): Uint8Array {
  let jwk: crypto.JsonWebKeyInput["key"];
  if (algorithm === coseAlgorithmES256) {
    const ec2 = publicKey.ec2();
    jwk = {
      kty: "EC",
      crv: "P-256",
      x: b64url(bigintToBytes(ec2.x, 32)),
      y: b64url(bigintToBytes(ec2.y, 32)),
    };
  } else if (algorithm === coseAlgorithmRS256) {
    const rsa = publicKey.rsa();
    jwk = {
      kty: "RSA",
      n: b64url(bigintToBytes(rsa.n, 256)),
      e: b64url(bigintToBytes(rsa.e)),
    };
  } else if (algorithm === coseAlgorithmEdDSA) {
    const okp = publicKey.okp();
    jwk = { kty: "OKP", crv: "Ed25519", x: b64url(okp.x) };
  } else {
    throw new Error(`Unsupported algorithm: ${algorithm}`);
  }
  const key = crypto.createPublicKey({ key: jwk, format: "jwk" });
  return new Uint8Array(key.export({ type: "spki", format: "der" }));
}

/**
 * Helper to convert bigint to bytes
 */
function bigintToBytes(value: bigint, minLength?: number): Uint8Array {
  const hex = value.toString(16);
  const paddedHex = hex.length % 2 === 0 ? hex : "0" + hex;
  const finalHex = paddedHex.padStart(minLength ? minLength * 2 : 0, "0");
  const bytes = new Uint8Array(finalHex.length / 2);
  for (let i = 0; i < bytes.length; i++) {
    bytes[i] = parseInt(finalHex.substring(i * 2, i * 2 + 2), 16);
  }
  return bytes;
}

/**
 * Verify an assertion signature over `authenticatorData || SHA-256(clientDataJSON)`.
 *
 * Uses `node:crypto` (not WebCrypto) so the algorithm-native signature
 * encodings authenticators produce verify directly: ES256 (DER-encoded ECDSA),
 * RS256 (RSASSA-PKCS1-v1_5), and EdDSA (Ed25519). The stored public key is the
 * SPKI DER produced by {@link serializePublicKey}.
 */
function verifySignature(
  publicKeyDer: Uint8Array,
  algorithm: number,
  authenticatorData: Uint8Array,
  clientDataJSON: Uint8Array,
  signature: Uint8Array,
): Effect.Effect<boolean, Errors.WebAuthnVerificationError> {
  return Effect.try({
    try: () => {
      const clientDataHash = crypto.createHash("sha256").update(clientDataJSON).digest();
      const message = Buffer.concat([Buffer.from(authenticatorData), clientDataHash]);
      const key = crypto.createPublicKey({
        key: Buffer.from(publicKeyDer),
        format: "der",
        type: "spki",
      });
      const sig = Buffer.from(signature);

      if (algorithm === coseAlgorithmES256 || algorithm === coseAlgorithmRS256) {
        return crypto.verify("sha256", message, key, sig);
      }
      if (algorithm === coseAlgorithmEdDSA) {
        // Ed25519 hashes internally; the digest algorithm must be null.
        return crypto.verify(null, message, key, sig);
      }
      throw new Error(`Unsupported algorithm: ${algorithm}`);
    },
    catch: (error) =>
      new Errors.WebAuthnVerificationError({
        message: "Failed to verify signature",
        cause: error,
      }),
  });
}

/**
 * Helper to compare two Uint8Arrays using timing-safe comparison
 */
function compareUint8Arrays(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) {
    return false;
  }
  const bufA = Buffer.from(a);
  const bufB = Buffer.from(b);
  return crypto.timingSafeEqual(bufA, bufB);
}

/**
 * Helper to encode Uint8Array to base64url
 */
function base64UrlEncode(buffer: Uint8Array): string {
  const base64 = Buffer.from(buffer).toString("base64");
  return base64.replace(/\+/g, "-").replace(/\//g, "_").replace(/=/g, "");
}
