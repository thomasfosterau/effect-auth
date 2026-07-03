/**
 * Google One Tap sign-in.
 *
 * The browser's One Tap prompt yields a `credential` — an OIDC `id_token`
 * signed by Google. This module verifies it against Google's published JWKS
 * (signature, `iss`, `aud` = your OAuth client id, `exp`) via the shared
 * {@link module:oauth} `verifyIdToken`, then finds-or-creates the user by
 * their verified email and issues a session.
 *
 * @module google-one-tap
 */
import { Context, Data, Effect, Layer } from "effect";
import type { AuthError } from "./Errors.js";
import { Hooks, type HookError } from "./Hooks.js";
import { SessionManagerTag } from "./Session.js";
import { OAuthUserStoreTag, verifyIdToken } from "./OAuth.js";
import type * as Types from "./Types.js";

/** Failure to verify a One Tap credential or complete the sign-in. */
export class GoogleOneTapError extends Data.TaggedError("GoogleOneTapError")<{
  readonly message: string;
  readonly cause?: unknown;
}> {}

/** Google's JWKS document location. */
export const GOOGLE_JWKS_ENDPOINT = "https://www.googleapis.com/oauth2/v3/certs";

/** The two issuer values Google mints `id_token`s under. */
export const GOOGLE_ISSUERS = ["https://accounts.google.com", "accounts.google.com"] as const;

/** Configuration for {@link makeGoogleOneTapService}. */
export interface GoogleOneTapConfig {
  /** Your Google OAuth client id — the credential's required `aud`. */
  readonly clientId: string;
  /** Override the JWKS endpoint (tests). Default {@link GOOGLE_JWKS_ENDPOINT}. */
  readonly jwksEndpoint?: string;
  /** Override the accepted issuers (tests). Default {@link GOOGLE_ISSUERS}. */
  readonly issuers?: readonly string[];
}

/** Result of a completed One Tap sign-in. */
export interface GoogleOneTapSignInResult {
  readonly user: Types.User;
  readonly session: Types.Session;
  readonly isNewUser: boolean;
  /** The verified id_token claims (sub, email, name, picture, ...). */
  readonly claims: Record<string, unknown>;
}

export interface GoogleOneTapService {
  /**
   * Verify a One Tap `credential` (id_token) and sign the user in:
   * find-or-create by the token's verified email, then issue a session.
   */
  readonly signIn: (
    credential: string,
  ) => Effect.Effect<
    GoogleOneTapSignInResult,
    GoogleOneTapError | AuthError | HookError,
    OAuthUserStoreTag | SessionManagerTag | Hooks
  >;
}

export class GoogleOneTapServiceTag extends Context.Service<
  GoogleOneTapServiceTag,
  GoogleOneTapService
>()("@effect-auth/GoogleOneTapService") {
  /**
   * Construct a Layer providing this service — the canonical form of
   * {@link GoogleOneTapServiceLayer}.
   */
  static readonly layer = (config: GoogleOneTapConfig) => GoogleOneTapServiceLayer(config);
}

// Public ergonomic alias
export const GoogleOneTapService = GoogleOneTapServiceTag;

export const makeGoogleOneTapService = (
  config: GoogleOneTapConfig,
): Effect.Effect<GoogleOneTapService, never> => {
  const jwksEndpoint = config.jwksEndpoint ?? GOOGLE_JWKS_ENDPOINT;
  const issuers = config.issuers ?? GOOGLE_ISSUERS;

  return Effect.succeed({
    signIn: (credential) =>
      Effect.gen(function* () {
        const userStore = yield* OAuthUserStoreTag;
        const sessionManager = yield* SessionManagerTag;

        // Signature/aud/exp via the shared verifier; `iss` is checked here
        // because Google mints tokens under two issuer values.
        const claims = yield* verifyIdToken(credential, {
          provider: "google-one-tap",
          jwksEndpoint,
          audience: config.clientId,
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

        let user = yield* userStore.getUserByEmail(normalized);
        const isNewUser = user === null;
        if (user === null) {
          user = yield* userStore.createUser({
            email: normalized,
            emailVerified: true,
            ...(typeof claims["name"] === "string" && { name: claims["name"] }),
            ...(typeof claims["picture"] === "string" && { image: claims["picture"] }),
          });
        }

        const session = yield* sessionManager.createSession(user.id);
        return { user, session, isNewUser, claims };
      }),
  } satisfies GoogleOneTapService);
};

export const GoogleOneTapServiceLayer = (config: GoogleOneTapConfig) =>
  Layer.effect(GoogleOneTapServiceTag, makeGoogleOneTapService(config));
