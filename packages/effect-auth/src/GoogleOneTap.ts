/**
 * Google One Tap sign-in: verifies the prompt's `id_token` against Google's
 * keys and finds or creates the user. A server nonce blocks replay: mint it
 * with `createNonce`, pass it as `data-nonce`, and hand the unhashed nonce to
 * `signIn`, which consumes it. Provide a {@link GoogleOneTapNonceStore}.
 *
 * @module google-one-tap
 */
import { Clock, Context, Data, Effect, Layer } from "effect";
import * as P from "effect/Predicate";
import { Digest, SecureRandom } from "effect/crypto";
import type { HttpClient } from "effect/http";
import * as OutboundHttp from "./OutboundHttp.ts";
import type { AuthError } from "./Errors.ts";
import type { HookError } from "./Hooks.ts";
import * as PlatformCrypto from "./PlatformCrypto.ts";
import { SessionService } from "./SessionService.ts";
import {
  EmailPasswordStore,
  sessionOrChallenge,
  type SessionOrChallenge,
} from "./email/EmailPassword.ts";
import { firstProofServices, userForProvenEmail } from "./FirstProof.ts";
import { OAuthUserStore, generateNonce, verifyIdToken } from "./oauth/OAuth.ts";
import { IdentifierStore, findIdentifierOwner } from "./Identifier.ts";
import { UserStore } from "./UserStore.ts";
import { tokenHasher } from "./TokenHash.ts";
import type * as Types from "./Types.ts";
import { normalizeEmail } from "./utils.ts";

/** Failure to verify a One Tap credential or complete the sign-in. */
export class GoogleOneTapError extends Data.TaggedError("GoogleOneTapError")<{
  readonly message: string;
  readonly cause?: unknown;
}> {}

/** Google's JWKS document location. */
export const GOOGLE_JWKS_ENDPOINT = "https://www.googleapis.com/oauth2/v3/certs";

/** The two issuer values Google mints `id_token`s under. */
export const GOOGLE_ISSUERS = ["https://accounts.google.com", "accounts.google.com"] as const;

// ---------------------------------------------------------------------------
// Nonce store
// ---------------------------------------------------------------------------

/** A single stored nonce entry. */
export interface GoogleOneTapNonceEntry {
  /** Epoch-millisecond expiry. */
  readonly expiresAt: number;
}

/**
 * Operations on the server-side nonce store used for One Tap replay
 * protection.
 */
export class GoogleOneTapNonceStore extends Context.Service<
  GoogleOneTapNonceStore,
  {
    /** Persist a nonce until `expiresAt` (epoch-ms). */
    readonly create: (nonce: string, expiresAt: number) => Effect.Effect<void, AuthError>;
    /** Return the stored entry, or `null` if absent. */
    readonly get: (nonce: string) => Effect.Effect<GoogleOneTapNonceEntry | null, AuthError>;
    /** Remove a nonce (called after a successful or failed consume). */
    readonly delete: (nonce: string) => Effect.Effect<void, AuthError>;
  }
>()("@effect-auth/GoogleOneTapNonceStore") {}

// ---------------------------------------------------------------------------
// Config & result types
// ---------------------------------------------------------------------------

/** Configuration for {@link make}. */
export interface GoogleOneTapConfig {
  /** Your Google OAuth client id — the credential's required `aud`. */
  readonly clientId: string;
  /** Override the JWKS endpoint (tests). Default {@link GOOGLE_JWKS_ENDPOINT}. */
  readonly jwksEndpoint?: string;
  /** Override the accepted issuers (tests). Default {@link GOOGLE_ISSUERS}. */
  readonly issuers?: readonly string[];
  /**
   * How long a generated nonce is valid, in milliseconds. Default 600 000 ms
   * (10 minutes) — long enough for a slow user, short enough to limit the
   * replay window.
   */
  readonly nonceTtlMs?: number;
}

/** Result of a completed One Tap sign-in. */
export type GoogleOneTapSignInResult = {
  readonly user: Types.User;
  readonly isNewUser: boolean;
  /** The verified id_token claims (sub, email, name, picture, ...). */
  readonly claims: Types.JsonObject;
} & SessionOrChallenge;

/**
 * Google One Tap sign-in: issues a nonce, verifies the One Tap credential against Google's JWKS, and signs in by the verified email.
 *
 * Requires `GoogleOneTapNonceStore`, `OAuthUserStore`, `UserStore`, `IdentifierStore`, `SessionService` and `EmailPasswordStore`.
 *
 * Promoting an address held unverified to verified first clears the
 * account's password and revokes its sessions, through `EmailPasswordStore`:
 * the account was created by a sign-up that proved nothing about the
 * address, so its password may be someone else's.
 */
export class GoogleOneTapService extends Context.Service<
  GoogleOneTapService,
  {
    /**
     * Generate a server-side nonce, persist it, and return the raw value.
     *
     * Pass the returned nonce to Google's One Tap library (`data-nonce`).
     * Google hashes it (SHA-256 hex) before embedding it in the id_token, but
     * you always work with the **unhashed** value.
     */
    readonly createNonce: Effect.Effect<string, GoogleOneTapError | AuthError>;

    /**
     * Verify a One Tap `credential` (id_token) and sign the user in:
     * find-or-create by the token's verified email, then issue a session.
     *
     * `nonce` must be the **unhashed** value returned by {@link createNonce}.
     * The call consumes the nonce — a second call with the same credential /
     * nonce pair is rejected even if the id_token has not yet expired.
     */
    readonly signIn: (
      credential: string,
      nonce: string,
    ) => Effect.Effect<GoogleOneTapSignInResult, GoogleOneTapError | AuthError | HookError>;
  }
>()("@effect-auth/GoogleOneTapService") {
  /**
   * Construct a Layer providing this service.
   */
  static readonly layer = (config: GoogleOneTapConfig) =>
    Layer.effect(GoogleOneTapService, make(config)).pipe(Layer.provide(PlatformCrypto.layer));
}

// ---------------------------------------------------------------------------
// Implementation
// ---------------------------------------------------------------------------

export const make = (
  config: GoogleOneTapConfig,
): Effect.Effect<
  typeof GoogleOneTapService.Service,
  never,
  | GoogleOneTapNonceStore
  | OAuthUserStore
  | IdentifierStore
  | UserStore
  | SessionService
  | EmailPasswordStore
  | SecureRandom.SecureRandom
  | Digest.Digest
  | HttpClient.HttpClient
> =>
  Effect.gen(function* () {
    const outbound = yield* OutboundHttp.resolve();
    const jwksEndpoint = config.jwksEndpoint ?? GOOGLE_JWKS_ENDPOINT;
    const issuers = config.issuers ?? GOOGLE_ISSUERS;
    const nonceTtlMs = config.nonceTtlMs ?? 600_000;

    const nonceStore = yield* GoogleOneTapNonceStore;
    const userStore = yield* OAuthUserStore;
    const identifiers = yield* IdentifierStore;
    const users = yield* UserStore;
    const sessionManager = yield* SessionService;
    const passwords = yield* EmailPasswordStore;
    const firstProof = yield* firstProofServices({
      identifiers,
      passwords,
      sessions: sessionManager,
    });
    const crypto = yield* SecureRandom.SecureRandom;
    // Google embeds the SHA-256 hex digest of the nonce, not the raw nonce,
    // in the id_token `nonce` claim.
    const hashNonce = yield* tokenHasher;

    return {
      createNonce: Effect.gen(function* () {
        const nonce = yield* generateNonce.pipe(
          Effect.provideService(SecureRandom.SecureRandom, crypto),
        );
        yield* nonceStore
          .create(nonce, (yield* Clock.currentTimeMillis) + nonceTtlMs)
          .pipe(Effect.mapError((e) => new GoogleOneTapError({ message: e.message, cause: e })));
        return nonce;
      }).pipe(Effect.withSpan("GoogleOneTapService.createNonce")),

      signIn: Effect.fn("GoogleOneTapService.signIn")(function* (
        credential: string,
        nonce: string,
      ) {
        // --- Nonce lifecycle: verify present, unexpired, then consume --------
        const entry = yield* nonceStore
          .get(nonce)
          .pipe(Effect.mapError((e) => new GoogleOneTapError({ message: e.message, cause: e })));
        if (entry === null) {
          return yield* new GoogleOneTapError({ message: "Unknown or already-used nonce" });
        }
        if ((yield* Clock.currentTimeMillis) > entry.expiresAt) {
          yield* Effect.ignore(nonceStore.delete(nonce));
          return yield* new GoogleOneTapError({ message: "Nonce has expired" });
        }
        // Consume before verifying the token so the nonce cannot be reused
        // even if verification fails.
        yield* nonceStore
          .delete(nonce)
          .pipe(Effect.mapError((e) => new GoogleOneTapError({ message: e.message, cause: e })));

        // --- Signature / aud / exp / nonce via the shared verifier -----------
        const claims = yield* verifyIdToken(credential, {
          provider: "google-one-tap",
          jwksEndpoint,
          audience: config.clientId,
          nonce: yield* hashNonce(nonce),
        }).pipe(
          OutboundHttp.provide(outbound),
          Effect.mapError((e) => new GoogleOneTapError({ message: e.message, cause: e })),
        );

        if (!P.isString(claims["iss"]) || !issuers.includes(claims["iss"])) {
          return yield* new GoogleOneTapError({ message: "id_token issuer mismatch" });
        }

        const email = claims["email"];
        if (!P.isString(email) || claims["email_verified"] !== true) {
          return yield* new GoogleOneTapError({
            message: "Google did not attest a verified email address",
          });
        }
        const normalized = normalizeEmail(email);

        const found = yield* findIdentifierOwner(
          identifiers,
          users.get,
          "email",
          normalized,
          () => new GoogleOneTapError({ message: "Account is unavailable" }),
        );
        const isNewUser = found.user === null;
        // Google attested the address as verified.
        const user = yield* userForProvenEmail(
          firstProof,
          found,
          normalized,
          (identifier) =>
            userStore.createUser({
              ...(P.isString(claims["name"]) && { name: claims["name"] }),
              ...(P.isString(claims["picture"]) && { image: claims["picture"] }),
              identifier,
            }),
          () => new GoogleOneTapError({ message: "This email is already in use" }),
        );

        const issued = yield* sessionOrChallenge(sessionManager, user, "google-one-tap");
        return { user, ...issued, isNewUser, claims } satisfies GoogleOneTapSignInResult;
      }),
    };
  });
