/**
 * Google One Tap sign-in.
 *
 * The browser's One Tap prompt yields a `credential` — an OIDC `id_token`
 * signed by Google. This module verifies it against Google's published JWKS
 * (signature, `iss`, `aud` = your OAuth client id, `exp`, `nonce`) via the
 * shared {@link module:oauth} `verifyIdToken`, then finds-or-creates the user
 * by their verified email and issues a session.
 *
 * ## Nonce / replay protection
 *
 * To prevent a captured id_token from being replayed, this module enforces a
 * server-side nonce:
 *
 * 1. Call `createNonce()` (or `GET /sign-in/google-one-tap/nonce`) before
 *    rendering the One Tap prompt. Pass the returned nonce as the `data-nonce`
 *    attribute to Google's One Tap library.
 * 2. Google embeds the nonce (SHA-256 hex-hashed per spec) in the id_token's
 *    `nonce` claim. Pass the **unhashed** nonce alongside the credential when
 *    calling `signIn` (or `POST /sign-in/google-one-tap`).
 * 3. `signIn` verifies that the stored nonce matches and consumes it — a
 *    replayed credential is rejected even if it is otherwise still valid.
 *
 * Provide a {@link GoogleOneTapNonceStore} (e.g. `GoogleOneTapNonceStoreKV`
 * from `KeyValueStores`) to the service's context.
 *
 * @module google-one-tap
 */
import { Context, Crypto, Data, Effect, Layer } from "effect";
import type { AuthError } from "./Errors.ts";
import type { HookError } from "./Hooks.ts";
import * as PlatformCrypto from "./PlatformCrypto.ts";
import { SessionService } from "./session/SessionService.ts";
import { OAuthUserStore, generateNonce, verifyIdToken } from "./oauth/OAuth.ts";
import { claimIdentifier, IdentifierStore, makeIdentifier } from "./Identifier.ts";
import { UserStore } from "./session/UserStore.ts";
import { hashToken } from "./TokenHash.ts";
import type * as Types from "./Types.ts";

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
export interface GoogleOneTapSignInResult {
  readonly user: Types.User;
  readonly session: Types.Session;
  readonly isNewUser: boolean;
  /** The verified id_token claims (sub, email, name, picture, ...). */
  readonly claims: Record<string, unknown>;
}

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
    readonly createNonce: () => Effect.Effect<string, GoogleOneTapError | AuthError>;

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

/**
 * Google embeds the SHA-256 hex digest of the nonce — not the raw nonce —
 * in the id_token `nonce` claim.
 */
const hashNonce = hashToken;

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
  | Crypto.Crypto
> =>
  Effect.gen(function* () {
    const jwksEndpoint = config.jwksEndpoint ?? GOOGLE_JWKS_ENDPOINT;
    const issuers = config.issuers ?? GOOGLE_ISSUERS;
    const nonceTtlMs = config.nonceTtlMs ?? 600_000;

    const nonceStore = yield* GoogleOneTapNonceStore;
    const userStore = yield* OAuthUserStore;
    const identifiers = yield* IdentifierStore;
    const users = yield* UserStore;
    const sessionManager = yield* SessionService;
    const crypto = yield* Crypto.Crypto;

    return {
      createNonce: Effect.fn("GoogleOneTapService.createNonce")(function* () {
        const nonce = yield* generateNonce().pipe(Effect.provideService(Crypto.Crypto, crypto));
        yield* nonceStore
          .create(nonce, Date.now() + nonceTtlMs)
          .pipe(Effect.mapError((e) => new GoogleOneTapError({ message: e.message, cause: e })));
        return nonce;
      }),

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
        if (Date.now() > entry.expiresAt) {
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
          nonce: hashNonce(nonce),
        }).pipe(Effect.mapError((e) => new GoogleOneTapError({ message: e.message, cause: e })));

        if (typeof claims["iss"] !== "string" || !issuers.includes(claims["iss"])) {
          return yield* new GoogleOneTapError({ message: "id_token issuer mismatch" });
        }

        const email = claims["email"];
        if (typeof email !== "string" || claims["email_verified"] !== true) {
          return yield* new GoogleOneTapError({
            message: "Google did not attest a verified email address",
          });
        }
        const normalized = email.trim().toLowerCase();

        const identifier = yield* identifiers.getByValue("email", normalized);
        let user = identifier === null ? null : yield* users.get(identifier.userId);
        if (identifier !== null && user === null) {
          return yield* new GoogleOneTapError({ message: "Account is unavailable" });
        }
        const isNewUser = user === null;
        if (user === null) {
          user = yield* userStore.createUser({
            ...(typeof claims["name"] === "string" && { name: claims["name"] }),
            ...(typeof claims["picture"] === "string" && { image: claims["picture"] }),
          });
          // Google attested the address as verified.
          yield* claimIdentifier(
            identifiers,
            makeIdentifier({
              userId: user.id,
              type: "email",
              value: normalized,
              verified: true,
              verifiedAt: new Date(),
            }),
          ).pipe(
            Effect.catchTag("IdentifierTakenError", () =>
              Effect.fail(new GoogleOneTapError({ message: "This email is already in use" })),
            ),
          );
        } else if (identifier !== null && !identifier.verified) {
          yield* identifiers.setVerified(identifier.id, new Date());
        }

        const session = yield* sessionManager.createSession(user.id);
        return { user, session, isNewUser, claims };
      }),
    };
  });
