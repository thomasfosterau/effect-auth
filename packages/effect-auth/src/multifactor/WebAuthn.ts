/**
 * WebAuthn types and service for passkey authentication.
 * Following Copenhagen/Oslo guidelines for WebAuthn implementation.
 */

import { Clock, Context, Data, Effect, Layer, Result } from "effect";
import * as Arr from "effect/Array";
import * as Schema from "effect/Schema";
import { Base64, Base64Url, Hex } from "effect/encoding";
import { Digest, SecureRandom } from "effect/crypto";
import {
  parseAttestationObject,
  parseClientDataJSON,
  parseAuthenticatorData,
  coseAlgorithmES256,
  coseAlgorithmRS256,
  coseAlgorithmEdDSA,
  coseEllipticCurveP256,
  COSEPublicKey,
  ClientDataType,
  type ClientData,
  type AuthenticatorData,
} from "./WebAuthnCodec.ts";
import * as Cipher from "../Cipher.ts";
import * as Errors from "../Errors.ts";
import { type HookError, Hooks } from "../Hooks.ts";
import * as Obs from "../Observability.ts";
import * as PlatformCrypto from "../PlatformCrypto.ts";
import { timingSafeEqualBytes } from "../TokenHash.ts";

/**
 * The WebAuthn ceremony a challenge was issued for: `"registration"`
 * (`navigator.credentials.create()`) or `"authentication"`
 * (`navigator.credentials.get()`). A challenge is redeemable only by the
 * ceremony it was issued for (#591).
 */
export const WebAuthnCeremony = Schema.Literals(["registration", "authentication"]);

/** The WebAuthn ceremony a challenge was issued for. */
export type WebAuthnCeremony = typeof WebAuthnCeremony.Type;

/**
 * Whether `value` names a {@link WebAuthnCeremony}. Store adapters read a
 * stored ceremony back through it; anything else reads as a missing challenge.
 */
export const isWebAuthnCeremony: (value: unknown) => value is WebAuthnCeremony =
  Schema.is(WebAuthnCeremony);

/**
 * Represents a WebAuthn challenge used during registration and authentication
 */
export interface WebAuthnChallenge {
  /** Challenge bytes (random value) */
  challenge: Uint8Array;
  /** The ceremony this challenge was issued for; the other ceremony refuses it. */
  ceremony: WebAuthnCeremony;
  /** Expiration timestamp */
  expiresAt: number;
  /**
   * The user the challenge was issued to. Always set on a registration
   * challenge; set on a bound authentication challenge and absent on a
   * discoverable (usernameless) one.
   */
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
  /**
   * User-verification requirement (default `"preferred"`), advertised in both
   * ceremonies. `"required"` is also enforced: a registration or assertion
   * whose authenticator data lacks the UV flag is refused. Under
   * `"preferred"` or `"discouraged"` the flag is reported (`userVerified` on
   * the results) for the host to act on.
   */
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
 * The authenticator-data flags of a verified ceremony (WebAuthn Level 3
 * §6.1): whether the user was verified (UV), and the credential's backup
 * eligibility (BE) and backup state (BS).
 */
export interface AuthenticatorFlags {
  /** UV: the authenticator verified the user (PIN, biometric), not only their presence. */
  readonly userVerified: boolean;
  /** BE: the credential may be backed up (a multi-device passkey). */
  readonly backupEligible: boolean;
  /** BS: the credential is backed up right now. */
  readonly backupState: boolean;
}

/**
 * Result of successful registration
 */
export interface RegistrationResult extends AuthenticatorFlags {
  /** The newly created credential */
  credential: WebAuthnCredential;
}

/**
 * Result of successful authentication
 */
export interface AuthenticationResult extends AuthenticatorFlags {
  /** The credential used for authentication */
  credential: WebAuthnCredential;
  /** Updated counter value */
  newCounter: number;
}

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
 *
 * Context tag for ChallengeStore
 */
export class ChallengeStore extends Context.Service<
  ChallengeStore,
  {
    /** Store a challenge with its ceremony, replacing one with the same bytes. */
    create: (challenge: WebAuthnChallenge) => Effect.Effect<WebAuthnChallenge, Errors.AuthError>;
    /**
     * Get a challenge by its value, or `null` when no such challenge exists.
     * A stored challenge whose ceremony is missing or unknown (one written
     * before ceremonies were recorded, #591) reads as `null`.
     */
    get: (challenge: Uint8Array) => Effect.Effect<WebAuthnChallenge | null, Errors.AuthError>;
    /** Delete a challenge */
    delete: (challenge: Uint8Array) => Effect.Effect<void, Errors.AuthError>;
  }
>()("@effect-auth/ChallengeStore") {}

/**
 * WebAuthn credential store interface
 * Implement this to store credentials in your database
 *
 * Context tag for CredentialStore
 */
export class CredentialStore extends Context.Service<
  CredentialStore,
  {
    /**
     * Store a credential. The service refuses an id that is already
     * registered before it calls this; a store with a unique key on the id
     * should still fail (`AuthError`) rather than overwrite a concurrent
     * registration of the same id.
     */
    create: (credential: WebAuthnCredential) => Effect.Effect<WebAuthnCredential, Errors.AuthError>;
    /** Get a credential by ID, or `null` when no such credential exists. */
    get: (credentialId: string) => Effect.Effect<WebAuthnCredential | null, Errors.AuthError>;
    /** Resolve a credential by its raw credential ID (base64url-encoded); used on the discoverable/usernameless login path. */
    getByCredentialId: (
      credentialId: string,
    ) => Effect.Effect<WebAuthnCredential | null, Errors.AuthError>;
    /** Update a credential (e.g., counter) */
    update: (credential: WebAuthnCredential) => Effect.Effect<WebAuthnCredential, Errors.AuthError>;
    /** Delete a credential */
    delete: (credentialId: string) => Effect.Effect<void, Errors.AuthError>;
    /** List all credentials for a user */
    listByUserId: (
      userId: string,
    ) => Effect.Effect<readonly WebAuthnCredential[], Errors.AuthError>;
    /**
     * Delete every credential `userId` registered; a no-op when they hold
     * none. Deleting a user calls it before the user row goes (#601), and the
     * first proof of an address calls it too.
     */
    deleteByUserId: (userId: string) => Effect.Effect<void, Errors.AuthError>;
  }
>()("@effect-auth/CredentialStore") {}

/**
 * Helper to decode base64url to Uint8Array
 */
export function base64UrlDecode(str: string): Uint8Array {
  // Convert base64url to base64
  const unpadded = str.replace(/-/g, "+").replace(/_/g, "/");
  // Add padding if needed
  const base64 = unpadded.padEnd(unpadded.length + ((4 - (unpadded.length % 4)) % 4), "=");
  // Input that is not base64url decodes to no bytes, which matches nothing.
  return Result.getOrElse(Base64.decode(base64), () => new Uint8Array(0));
}

/** A ceremony response that fails a verification step. */
const verificationError = (message: string) => new Errors.WebAuthnVerificationError({ message });

/**
 * Create a WebAuthn service
 */
export const make = (
  config: WebAuthnConfig,
): Effect.Effect<
  typeof WebAuthnService.Service,
  never,
  ChallengeStore | CredentialStore | Hooks | SecureRandom.SecureRandom | Digest.Digest
> =>
  Effect.gen(function* () {
    const challengeStore = yield* ChallengeStore;
    const credentialStore = yield* CredentialStore;
    const hooks = yield* Hooks;
    const crypto = yield* SecureRandom.SecureRandom;
    const digest = yield* Digest.Digest;

    /**
     * Fail a passkey sign-in that names no user (an unknown or expired
     * challenge, an unknown credential, or another user's credential) after
     * firing the `beforeAuthenticate` gate unkeyed, so the per-IP limit
     * counts it (#678).
     */
    const refuseUnkeyed = <E>(error: E): Effect.Effect<never, E | HookError> =>
      hooks.beforeAuthenticate({ method: "passkey" }).pipe(Effect.andThen(Effect.fail(error)));

    const challengeExpiresIn = config.challengeExpiresIn ?? 5 * 60 * 1000; // 5 minutes default

    const generateChallenge = (): Effect.Effect<Uint8Array> => crypto.randomBytes(32);

    const userVerification = config.userVerification ?? "preferred";
    const origins: readonly string[] = Arr.ensure(config.expectedOrigin);

    /**
     * The stored challenge, once it is known to be live and issued for
     * `ceremony`. A challenge issued for the other ceremony is refused and
     * left in place, so presenting it here cannot cancel the ceremony it
     * belongs to; an expired one is deleted.
     */
    const liveChallenge = Effect.fnUntraced(function* (
      challenge: Uint8Array,
      ceremony: WebAuthnCeremony,
    ) {
      const stored = yield* challengeStore.get(challenge);
      if (stored === null) {
        return yield* new Errors.ChallengeNotFoundError({ message: "Challenge not found" });
      }
      if (stored.ceremony !== ceremony) {
        return yield* verificationError(
          `Challenge was issued for ${stored.ceremony}, not ${ceremony}`,
        );
      }
      if ((yield* Clock.currentTimeMillis) > stored.expiresAt) {
        yield* challengeStore.delete(challenge);
        return yield* new Errors.ChallengeExpiredError({ message: "Challenge has expired" });
      }
      return stored;
    });

    /**
     * The first steps of a passkey sign-in: the live authentication challenge
     * and the credential the assertion names (the bound user's, on a bound
     * challenge), then the `beforeAuthenticate` gate for the credential's
     * user, before the signature is checked or the challenge spent (#678).
     * Answers the credential.
     */
    const resolveAssertion = Effect.fnUntraced(function* (
      challenge: Uint8Array,
      response: AuthenticationResponse,
    ) {
      const storedChallenge = yield* liveChallenge(challenge, "authentication").pipe(
        Effect.catchTags({
          ChallengeNotFoundError: (error) => refuseUnkeyed(error),
          ChallengeExpiredError: (error) => refuseUnkeyed(error),
          WebAuthnVerificationError: (error) => refuseUnkeyed(error),
        }),
      );

      // On the usernameless path the credentialId is the lookup key; on the
      // bound path we use the same route for consistency.
      const credentialId = base64UrlEncode(response.credentialId);
      const credential = yield* credentialStore.get(credentialId);
      if (credential === null) {
        return yield* refuseUnkeyed(
          new Errors.CredentialNotFoundError({ message: "Credential not found", credentialId }),
        );
      }

      // Bound challenge: the credential must belong to the expected user.
      if (storedChallenge.userId !== undefined && credential.userId !== storedChallenge.userId) {
        return yield* refuseUnkeyed(
          new Errors.WebAuthnVerificationError({
            message: "Credential does not belong to the expected user",
          }),
        );
      }

      yield* hooks.beforeAuthenticate({
        method: "passkey",
        identifier: { type: "user", value: credential.userId },
        userId: credential.userId,
      });
      return credential;
    });

    /** The `clientDataJSON` checks (WebAuthn §7.1 steps 7-10, §7.2 steps 11-14). */
    const verifyClientData = Effect.fnUntraced(function* (
      clientDataJSON: Uint8Array,
      type: ClientDataType,
      challenge: Uint8Array,
    ) {
      const clientData: ClientData = yield* Effect.try({
        try: () => parseClientDataJSON(clientDataJSON),
        catch: (error) =>
          new Errors.WebAuthnVerificationError({
            message: "Failed to parse client data JSON",
            cause: error,
          }),
      });
      if (clientData.type !== type) {
        return yield* verificationError(`Invalid type: ${clientData.type}`);
      }
      if (!compareUint8Arrays(clientData.challenge, challenge)) {
        return yield* verificationError("Challenge mismatch");
      }
      if (!origins.includes(clientData.origin)) {
        return yield* verificationError(`Invalid origin: ${clientData.origin}`);
      }
      // A ceremony run inside a cross-origin iframe is never expected here.
      if (clientData.crossOrigin) {
        return yield* verificationError("Cross-origin ceremonies are not accepted");
      }
      return clientData;
    });

    /** RP ID hash and flag checks shared by both ceremonies (§7.1 steps 14-18, §7.2 steps 15-19). */
    const verifyAuthenticatorData = Effect.fnUntraced(function* (
      authenticatorData: AuthenticatorData,
    ) {
      if (!authenticatorData.verifyRelyingPartyIdHash(config.relyingPartyId)) {
        return yield* verificationError("Invalid relying party ID hash");
      }
      if (!authenticatorData.userPresent) {
        return yield* verificationError("User not present");
      }
      if (userVerification === "required" && !authenticatorData.userVerified) {
        return yield* verificationError("User verification is required");
      }
      // A credential that cannot be backed up cannot be backed up now.
      if (!authenticatorData.backupEligible && authenticatorData.backupState) {
        return yield* verificationError(
          "Backup state set on a credential that is not backup eligible",
        );
      }
      const flags: AuthenticatorFlags = {
        userVerified: authenticatorData.userVerified,
        backupEligible: authenticatorData.backupEligible,
        backupState: authenticatorData.backupState,
      };
      return flags;
    });

    /** The attested credential's id and stored public key (§7.1 steps 19-25). */
    const attestedCredential = Effect.fnUntraced(function* (
      authenticatorData: AuthenticatorData,
      reportedId: Uint8Array,
    ) {
      const attested = authenticatorData.credential;
      if (attested === null) {
        return yield* verificationError("No credential in authenticator data");
      }
      // The stored id is the one the authenticator attested (at most 1023
      // bytes), and it must be the id the client reported.
      if (attested.id.byteLength > 1023) {
        return yield* verificationError("Credential ID is longer than 1023 bytes");
      }
      if (!compareUint8Arrays(attested.id, reportedId)) {
        return yield* verificationError("Credential ID does not match the attested credential");
      }
      const algorithm = yield* Effect.try({
        try: () => attested.publicKey.algorithm(),
        catch: (error) =>
          new Errors.WebAuthnVerificationError({
            message: "Invalid credential public key",
            cause: error,
          }),
      });
      // ES256, RS256, and EdDSA are supported.
      if (!Arr.some(SUPPORTED_COSE_ALGORITHMS, (supported) => supported === algorithm)) {
        return yield* verificationError(
          `Unsupported algorithm: ${algorithm}. Supported: ES256 (-7), RS256 (-257), EdDSA (-8).`,
        );
      }
      const publicKey = yield* Effect.try({
        try: () => serializePublicKey(attested.publicKey, algorithm),
        catch: (error) =>
          new Errors.WebAuthnVerificationError({
            message: "Invalid credential public key",
            cause: error,
          }),
      });
      return { id: base64UrlEncode(attested.id), algorithm, publicKey };
    });

    return {
      generateRegistrationChallenge: Effect.fn("WebAuthnService.generateRegistrationChallenge")(
        function* (user: WebAuthnUser) {
          // Generate random challenge (32 bytes = 256 bits)
          const challenge: Uint8Array = yield* generateChallenge();
          const expiresAt = (yield* Clock.currentTimeMillis) + challengeExpiresIn;

          yield* challengeStore.create({
            challenge,
            ceremony: "registration",
            expiresAt,
            userId: user.id,
          });

          // Exclude the user's existing credentials to prevent re-registering
          // the same authenticator.
          const existing = yield* credentialStore.listByUserId(user.id);
          const excludeCredentials = existing.map((c): PublicKeyCredentialDescriptor =>
            c.transports === undefined
              ? { type: "public-key", id: c.id }
              : { type: "public-key", id: c.id, transports: c.transports },
          );

          const authenticatorSelection: AuthenticatorSelectionCriteria = {
            ...(config.residentKey && {
              residentKey: config.residentKey,
              requireResidentKey: config.residentKey === "required",
            }),
            userVerification,
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
        },
      ),

      verifyRegistration: Effect.fn("WebAuthnService.verifyRegistration")(
        (userId: string, challenge: Uint8Array, response: RegistrationResponse) =>
          Effect.gen(function* () {
            const storedChallenge = yield* liveChallenge(challenge, "registration");

            // The credential is filed under the signed-in user the host passes,
            // and only on a challenge that was issued to that same user.
            if (storedChallenge.userId !== userId) {
              return yield* verificationError("Challenge was not issued to this user");
            }

            yield* verifyClientData(response.clientDataJSON, ClientDataType.Create, challenge);

            const authenticatorData: AuthenticatorData = yield* Effect.try({
              try: () => parseAttestationObject(response.attestationObject).authenticatorData,
              catch: (error) =>
                new Errors.WebAuthnVerificationError({
                  message: "Failed to parse attestation object",
                  cause: error,
                }),
            });

            const flags = yield* verifyAuthenticatorData(authenticatorData);
            const attested = yield* attestedCredential(authenticatorData, response.credentialId);

            // §7.1 step 26: an id that is already registered, to this user or
            // another, is refused rather than overwritten.
            if ((yield* credentialStore.get(attested.id)) !== null) {
              return yield* verificationError("Credential is already registered");
            }

            const credential: WebAuthnCredential = {
              id: attested.id,
              userId,
              publicKey: attested.publicKey,
              algorithm: attested.algorithm,
              counter: authenticatorData.signatureCounter,
              createdAt: yield* Clock.currentTimeMillis,
            };

            // Spend the challenge, then store the credential.
            yield* challengeStore.delete(challenge);
            yield* credentialStore.create(credential);

            return { credential, ...flags };
          }).pipe(
            Effect.withSpan(Obs.spanNames.webauthnRegister),
            Effect.tap(() => Obs.recordWebAuthnRegistration("success")),
            Effect.tapError(() => Obs.recordWebAuthnRegistration("failure")),
          ),
      ),

      generateAuthenticationChallenge: Effect.fn("WebAuthnService.generateAuthenticationChallenge")(
        function* (userId?: string) {
          const challenge: Uint8Array = yield* generateChallenge();
          const expiresAt = (yield* Clock.currentTimeMillis) + challengeExpiresIn;

          yield* challengeStore.create({
            challenge,
            ceremony: "authentication",
            expiresAt,
            ...(userId !== undefined ? { userId } : {}),
          });

          return { challenge, expiresAt };
        },
      ),

      verifyAuthentication: Effect.fn("WebAuthnService.verifyAuthentication")(
        (challenge: Uint8Array, response: AuthenticationResponse) =>
          Effect.gen(function* () {
            const credential = yield* resolveAssertion(challenge, response);

            yield* verifyClientData(response.clientDataJSON, ClientDataType.Get, challenge);

            const authenticatorData: AuthenticatorData = yield* Effect.try({
              try: () => parseAuthenticatorData(response.authenticatorData),
              catch: (error) =>
                new Errors.WebAuthnVerificationError({
                  message: "Failed to parse authenticator data",
                  cause: error,
                }),
            });

            const flags = yield* verifyAuthenticatorData(authenticatorData);

            // Verify counter (anti-replay protection)
            // If both counters are 0, the authenticator does not support counter-based replay protection
            // and the counter check must be skipped per WebAuthn specification.
            if (!(authenticatorData.signatureCounter === 0 && credential.counter === 0)) {
              if (authenticatorData.signatureCounter <= credential.counter) {
                return yield* verificationError(
                  "Invalid counter value (possible cloned authenticator)",
                );
              }
            }

            // Verify signature
            const verified = yield* verifySignature(
              digest,
              credential.publicKey,
              credential.algorithm,
              response.authenticatorData,
              response.clientDataJSON,
              response.signature,
            );

            if (!verified) {
              return yield* verificationError("Invalid signature");
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
              ...flags,
            };
          }).pipe(
            Effect.withSpan(Obs.spanNames.webauthnAuthenticate),
            Effect.tap(() => Obs.recordWebAuthnAuthentication("success")),
            Effect.tapError(() => Obs.recordWebAuthnAuthentication("failure")),
          ),
      ),

      listCredentials: Effect.fn("WebAuthnService.listCredentials")((userId: string) =>
        credentialStore.listByUserId(userId),
      ),

      deleteCredential: Effect.fn("WebAuthnService.deleteCredential")(function* (
        userId: string,
        credentialId: string,
      ) {
        const credential = yield* credentialStore.get(credentialId);
        if (credential === null) {
          return yield* new Errors.CredentialNotFoundError({
            message: "Credential not found",
            credentialId,
          });
        }
        if (credential.userId !== userId) {
          return yield* new Errors.AuthError({
            message: "Not authorized to delete this credential",
          });
        }
        return yield* credentialStore.delete(credentialId);
      }),

      renameCredential: Effect.fn("WebAuthnService.renameCredential")(function* (
        userId: string,
        credentialId: string,
        name: string,
      ) {
        const credential = yield* credentialStore.get(credentialId);
        if (credential === null) {
          return yield* new Errors.CredentialNotFoundError({
            message: "Credential not found",
            credentialId,
          });
        }
        if (credential.userId !== userId) {
          return yield* new Errors.AuthError({
            message: "Not authorized to rename this credential",
          });
        }
        return yield* credentialStore.update({ ...credential, name });
      }),
    };
  });

/**
 * WebAuthn service for managing passkey registration and authentication.
 *
 * Requires `ChallengeStore`, `CredentialStore` and `Hooks` (passkey sign-in
 * fires `beforeAuthenticate`, #678; provide `Hooks.Default` for no plugins).
 */
export class WebAuthnService extends Context.Service<
  WebAuthnService,
  {
    /** Generate a challenge for registration */
    generateRegistrationChallenge: (
      user: WebAuthnUser,
    ) => Effect.Effect<RegistrationChallenge, Errors.AuthError>;

    /**
     * Verify a registration response and store the attested credential under
     * `userId`. Pass the signed-in user's id, from the session, never from
     * the request: the challenge must be a registration challenge issued to
     * that same user. The stored credential id is the attested one, which
     * must equal `response.credentialId`; an id already registered is refused.
     */
    verifyRegistration: (
      userId: string,
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

    /**
     * Verify authentication response from client (passkey sign-in).
     *
     * Fires the `beforeAuthenticate` hook (method `"passkey"`, keyed on the
     * credential's user) before the signature is checked or the challenge
     * spent, and unkeyed before failing on an unknown or expired challenge,
     * an unknown credential or another user's credential (#678). A refusal
     * fails with the hook's error.
     */
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
      | HookError
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
>()("@effect-auth/WebAuthnService") {
  static readonly layer = (config: WebAuthnConfig) =>
    Layer.effect(WebAuthnService, make(config)).pipe(Layer.provide(PlatformCrypto.layer));
}

/** A COSE algorithm outside {@link SUPPORTED_COSE_ALGORITHMS} reached key handling. */
class UnsupportedAlgorithmError extends Data.TaggedError("UnsupportedAlgorithmError")<{
  readonly message: string;
}> {}

const b64url = (bytes: Uint8Array): string => Base64Url.encode(bytes);

/**
 * Serialize a COSE public key to SPKI DER for storage. Using a single
 * key-independent encoding (rather than a raw EC point) lets ES256, RS256, and
 * EdDSA credentials share one storage format and one verification path.
 */
function serializePublicKey(publicKey: COSEPublicKey, algorithm: number): Uint8Array {
  let jwk: Parameters<typeof Cipher.jwkToSpkiDer>[0];
  if (algorithm === coseAlgorithmES256) {
    const ec2 = publicKey.ec2();
    // ES256 is ECDSA over P-256 only (RFC 9053 §2.1).
    if (ec2.curve !== coseEllipticCurveP256) {
      throw new UnsupportedAlgorithmError({
        message: `ES256 key on curve ${ec2.curve}, not P-256`,
      });
    }
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
    throw new UnsupportedAlgorithmError({ message: `Unsupported algorithm: ${algorithm}` });
  }
  return Cipher.jwkToSpkiDer(jwk);
}

/**
 * Helper to convert bigint to bytes
 */
function bigintToBytes(value: bigint, minLength?: number): Uint8Array {
  const hex = value.toString(16);
  const paddedHex = hex.length % 2 === 0 ? hex : "0" + hex;
  const finalHex = paddedHex.padStart(minLength ? minLength * 2 : 0, "0");
  // `finalHex` is even-length hex by construction, so the decode cannot fail.
  return Result.getOrElse(Hex.decode(finalHex), () => new Uint8Array(0));
}

/**
 * Verify an assertion signature over `authenticatorData || SHA-256(clientDataJSON)`.
 *
 * Delegates to the raw asymmetric primitives in `Cipher.ts` (not WebCrypto),
 * so the algorithm-native signature encodings authenticators produce verify
 * directly: ES256 (DER-encoded ECDSA), RS256 (RSASSA-PKCS1-v1_5), and EdDSA
 * (Ed25519). The stored public key is the SPKI DER produced by
 * {@link serializePublicKey}.
 */
function verifySignature(
  digest: typeof Digest.Digest.Service,
  publicKeyDer: Uint8Array,
  algorithm: number,
  authenticatorData: Uint8Array,
  clientDataJSON: Uint8Array,
  signature: Uint8Array,
): Effect.Effect<boolean, Errors.WebAuthnVerificationError> {
  return Effect.gen(function* () {
    const clientDataHash = yield* digest.digest(Digest.sha256, clientDataJSON);

    return yield* Effect.try({
      try: () => {
        const message = new Uint8Array(authenticatorData.length + clientDataHash.length);
        message.set(authenticatorData, 0);
        message.set(clientDataHash, authenticatorData.length);

        if (algorithm === coseAlgorithmES256 || algorithm === coseAlgorithmRS256) {
          return Cipher.verifyDerSignature("sha256", publicKeyDer, message, signature);
        }
        if (algorithm === coseAlgorithmEdDSA) {
          // Ed25519 hashes internally; the digest algorithm must be null.
          return Cipher.verifyDerSignature(null, publicKeyDer, message, signature);
        }
        throw new UnsupportedAlgorithmError({ message: `Unsupported algorithm: ${algorithm}` });
      },
      catch: (error) =>
        new Errors.WebAuthnVerificationError({
          message: "Failed to verify signature",
          cause: error,
        }),
    });
  });
}

/**
 * Helper to compare two Uint8Arrays using timing-safe comparison
 */
function compareUint8Arrays(a: Uint8Array, b: Uint8Array): boolean {
  return timingSafeEqualBytes(a, b);
}

/**
 * Helper to encode Uint8Array to base64url
 */
function base64UrlEncode(buffer: Uint8Array): string {
  return Base64Url.encode(buffer);
}
