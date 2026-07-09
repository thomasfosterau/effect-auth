/**
 * OAuth 2.0 and OpenID Connect types for effect-auth
 *
 * Provides type definitions for OAuth2 flows, provider configurations,
 * and related data structures.
 */

import { Config, Context, Effect, Layer, Redacted } from "effect";
import { makeAes256GcmCipher } from "../Cipher.ts";
import * as Obs from "../Observability.ts";
import type { TokenCipher } from "../Cipher.ts";
export type { TokenCipher } from "../Cipher.ts";
export { makeAes256GcmCipher } from "../Cipher.ts";
import {
  AuthError,
  OAuthProviderError,
  OAuthStateNotFoundError,
  OAuthStateExpiredError,
  OAuthAccountNotLinkedError,
  OAuthMissingEmailError,
  OAuthAccountConflictError,
  OAuthAccountNotFoundError,
  OAuthNoRefreshTokenError,
  UserNotFoundError,
} from "../Errors.ts";
import { Hooks, type HookError } from "../Hooks.ts";
import { SessionManager } from "../Session.ts";
import type * as Types from "../Types.ts";
import { normalizeEmail } from "../utils.ts";

/**
 * OAuth2 provider configuration
 */
export interface OAuthProviderConfig {
  readonly clientId: string;
  readonly clientSecret: Redacted.Redacted<string>;
  readonly redirectUri: string;
  readonly authorizationEndpoint: string;
  readonly tokenEndpoint: string;
  readonly userInfoEndpoint?: string;
  readonly scopes: readonly string[];
  /**
   * Resolve the user profile from the OIDC `id_token` returned by the token
   * endpoint instead of calling {@link userInfoEndpoint}. Required for
   * providers that only expose identity via the id_token (e.g. Apple).
   * Needs {@link jwksEndpoint} and {@link issuer} for verification.
   */
  readonly getUserInfoFromIdToken?: boolean;
  /** JWKS URL used to verify the OIDC `id_token` signature. */
  readonly jwksEndpoint?: string;
  /** Expected `iss` claim when verifying an OIDC `id_token`. */
  readonly issuer?: string;
  /**
   * How to authenticate at the token endpoint. `"body"` (default) sends
   * `client_id`/`client_secret` in the form body; `"basic"` uses HTTP Basic
   * (required by Reddit, X/Twitter confidential clients, Dropbox, ...).
   */
  readonly tokenAuthMethod?: "body" | "basic";
  /** HTTP method for the userinfo request (default `"GET"`; Dropbox uses POST). */
  readonly userInfoMethod?: "GET" | "POST";
  /** Extra headers for the userinfo request (e.g. Twitch's `Client-Id`). */
  readonly userInfoHeaders?: Readonly<Record<string, string>>;
  /** Extra static query parameters appended to the authorization URL. */
  readonly authorizationParams?: Readonly<Record<string, string>>;
  /** Name of the client-id parameter (default `"client_id"`; TikTok uses `"client_key"`). */
  readonly clientIdParam?: string;
  /**
   * Normalize a provider-specific profile payload into {@link OAuthUserInfo}
   * (maps nested shapes such as Facebook's `picture.data.url` or Twitter's
   * `data` envelope). Applied to both userinfo and id_token profiles.
   */
  readonly mapProfile?: (raw: Record<string, unknown>) => OAuthUserInfo;
}

/**
 * OAuth2 state for CSRF protection
 */
export interface OAuthState {
  readonly state: string;
  readonly provider: string;
  readonly codeVerifier?: string; // For PKCE
  readonly nonce?: string; // For OIDC id_token replay protection
  readonly returnTo?: string;
  readonly createdAt: number;
  readonly expiresAt: number;
}

/**
 * OAuth account linking to user
 */
export interface OAuthAccount {
  readonly id: string;
  readonly userId: string;
  readonly provider: string;
  readonly providerId: string;
  readonly email?: string;
  readonly name?: string;
  readonly picture?: string;
  readonly accessToken: string;
  readonly refreshToken?: string;
  readonly expiresAt?: number;
  readonly createdAt: number;
  readonly updatedAt: number;
}

/**
 * OAuth2 token response
 */
export interface OAuthTokenResponse {
  readonly access_token: string;
  readonly token_type: string;
  readonly expires_in?: number;
  readonly refresh_token?: string;
  readonly scope?: string;
  readonly id_token?: string; // For OIDC
}

/**
 * User info from OAuth provider
 */
export interface OAuthUserInfo {
  readonly id: string;
  readonly email?: string;
  readonly email_verified?: boolean;
  readonly name?: string;
  readonly picture?: string;
  readonly given_name?: string;
  readonly family_name?: string;
  readonly locale?: string;
  readonly [key: string]: unknown;
}

/**
 * Authorization URL generation result
 */
export interface AuthorizationUrlResult {
  readonly url: string;
  readonly state: string;
  readonly codeVerifier?: string;
}

/**
 * OAuth callback result
 */
export interface OAuthCallbackResult {
  readonly account: OAuthAccount;
  readonly isNewUser: boolean;
  readonly user?: {
    readonly id: string;
    readonly email?: string;
    readonly name?: string;
  };
}

/**
 * Storage interface for OAuth state (temporary, Redis/memory)
 */
export interface OAuthStateStoreShape {
  readonly create: (state: OAuthState) => Effect.Effect<OAuthState, AuthError>;
  /** Get a pending state entry, or `null` when unknown/expired-and-purged. */
  readonly get: (state: string) => Effect.Effect<OAuthState | null, AuthError>;
  readonly delete: (state: string) => Effect.Effect<void, AuthError>;
}

/**
 * Storage interface for OAuth accounts (persistent, database)
 */
export interface OAuthAccountStoreShape {
  readonly create: (account: OAuthAccount) => Effect.Effect<OAuthAccount, AuthError>;
  readonly get: (
    provider: string,
    providerId: string,
  ) => Effect.Effect<OAuthAccount | null, AuthError>;
  readonly getByUserId: (userId: string) => Effect.Effect<readonly OAuthAccount[], AuthError>;
  readonly update: (account: OAuthAccount) => Effect.Effect<OAuthAccount, AuthError>;
  readonly linkToUser: (userId: string, account: OAuthAccount) => Effect.Effect<void, AuthError>;
  readonly unlinkFromUser: (userId: string, provider: string) => Effect.Effect<void, AuthError>;
  readonly delete: (provider: string, providerId: string) => Effect.Effect<void, AuthError>;
}

/**
 * Input for creating a user from an OAuth provider profile.
 */
export interface OAuthCreateUserInput {
  readonly email: string;
  readonly emailVerified: boolean;
  readonly name?: string;
  readonly image?: string;
}

/**
 * Minimal user store the OAuth sign-in flow needs to create or look up users
 * from provider profiles. Implement alongside {@link OAuthAccountStoreShape}.
 */
export interface OAuthUserStoreShape {
  readonly getUser: (userId: string) => Effect.Effect<Types.User, AuthError | UserNotFoundError>;
  readonly getUserByEmail: (email: string) => Effect.Effect<Types.User | null, AuthError>;
  readonly createUser: (input: OAuthCreateUserInput) => Effect.Effect<Types.User, AuthError>;
}

/**
 * Result of a complete OAuth sign-in (callback handled, user resolved or
 * created, account linked, session issued).
 */
export interface OAuthSignInResult {
  readonly user: Types.User;
  readonly account: OAuthAccount;
  readonly session: Types.Session;
  readonly isNewUser: boolean;
  readonly returnTo?: string;
}

/**
 * OAuth provider interface
 */
export interface OAuthProvider {
  readonly name: string;
  readonly config: OAuthProviderConfig;
  readonly generateAuthorizationUrl: (
    scopes?: readonly string[],
  ) => Effect.Effect<AuthorizationUrlResult, OAuthProviderError | AuthError, OAuthStateStore>;
  readonly exchangeCode: (
    code: string,
    codeVerifier?: string,
  ) => Effect.Effect<OAuthTokenResponse, OAuthProviderError>;
  readonly getUserInfo: (accessToken: string) => Effect.Effect<OAuthUserInfo, OAuthProviderError>;
  /**
   * Resolve the user profile from a token response. Dispatches on
   * {@link OAuthProviderConfig.getUserInfoFromIdToken}: verifies + decodes the
   * OIDC `id_token` (honouring `expectedNonce`) when set, otherwise calls the
   * userinfo endpoint with the access token. Prefer this over
   * {@link getUserInfo} in callback handling.
   */
  readonly getProfile: (
    tokens: OAuthTokenResponse,
    options?: { readonly expectedNonce?: string },
  ) => Effect.Effect<OAuthUserInfo, OAuthProviderError>;
}

/**
 * OAuth 2.0 and OpenID Connect implementation for effect-auth
 *
 * Provides a generic OAuth2 client with authorization code flow,
 * PKCE support, and pre-built provider configurations.
 *
 * @module oauth
 */
import * as crypto from "node:crypto";

/**
 * OAuth state store context tag
 */
export class OAuthStateStore extends Context.Service<OAuthStateStore, OAuthStateStoreShape>()(
  "@effect-auth/OAuthStateStore",
) {}

/**
 * OAuth account store context tag
 */
export class OAuthAccountStore extends Context.Service<OAuthAccountStore, OAuthAccountStoreShape>()(
  "@effect-auth/OAuthAccountStore",
) {}

/**
 * OAuth user store context tag
 */
export class OAuthUserStore extends Context.Service<OAuthUserStore, OAuthUserStoreShape>()(
  "@effect-auth/OAuthUserStore",
) {}

/**
 * Generate a cryptographically secure random state parameter
 */
export const generateState = (): Effect.Effect<string, never> =>
  Effect.sync(() => crypto.randomBytes(32).toString("base64url"));

/**
 * Generate PKCE code verifier and challenge
 */
export const generatePKCE = (): Effect.Effect<
  { codeVerifier: string; codeChallenge: string },
  never
> =>
  Effect.sync(() => {
    const codeVerifier = crypto.randomBytes(32).toString("base64url");
    const codeChallenge = crypto.createHash("sha256").update(codeVerifier).digest("base64url");
    return { codeVerifier, codeChallenge };
  });

/**
 * Generate a cryptographically secure random nonce for OIDC id_token replay
 * protection.
 */
export const generateNonce = (): Effect.Effect<string, never> =>
  Effect.sync(() => crypto.randomBytes(16).toString("base64url"));

const decodeJwtSegment = (segment: string): Record<string, unknown> =>
  JSON.parse(Buffer.from(segment, "base64url").toString("utf8")) as Record<string, unknown>;

/** A single JSON Web Key from a provider's JWKS document. */
interface ProviderJwk {
  readonly kid?: string;
  readonly alg?: string;
  readonly kty?: string;
  readonly [key: string]: unknown;
}

/**
 * Verify and decode an OIDC `id_token` (compact JWS) against a provider's
 * JWKS. Validates the signature (RS256, ES256, or EdDSA), then `iss`, `aud`,
 * `exp`, and — when supplied — `nonce`. Returns the decoded claims.
 */
export const verifyIdToken = (
  idToken: string,
  params: {
    readonly provider: string;
    readonly jwksEndpoint: string;
    readonly issuer?: string;
    readonly audience?: string;
    readonly nonce?: string;
    readonly now?: number;
  },
): Effect.Effect<Record<string, unknown>, OAuthProviderError> =>
  Effect.gen(function* () {
    const fail = (message: string) =>
      new OAuthProviderError({ message, provider: params.provider });

    const parts = idToken.split(".");
    if (parts.length !== 3) {
      return yield* fail("Malformed id_token");
    }
    const [headerSeg, payloadSeg, signatureSeg] = parts as [string, string, string];

    let header: Record<string, unknown>;
    let payload: Record<string, unknown>;
    try {
      header = decodeJwtSegment(headerSeg);
      payload = decodeJwtSegment(payloadSeg);
    } catch (cause) {
      return yield* new OAuthProviderError({
        message: "Failed to decode id_token",
        provider: params.provider,
        cause,
      });
    }

    const alg = header["alg"];
    if (alg !== "RS256" && alg !== "ES256" && alg !== "EdDSA") {
      return yield* fail(`Unsupported id_token algorithm: ${String(alg)}`);
    }

    const response = yield* Effect.tryPromise({
      try: () => fetch(params.jwksEndpoint, { headers: { Accept: "application/json" } }),
      catch: (cause) =>
        new OAuthProviderError({
          message: `Failed to fetch JWKS for ${params.provider}`,
          provider: params.provider,
          cause,
        }),
    });
    if (!response.ok) {
      return yield* fail(`JWKS request failed with status ${response.status}`);
    }
    const jwks = (yield* Effect.promise(() => response.json())) as {
      keys?: readonly ProviderJwk[];
    };
    const keys = jwks.keys ?? [];
    const kid = header["kid"];
    const jwk = keys.find((k) => k.kid === kid) ?? (keys.length === 1 ? keys[0] : undefined);
    if (!jwk) {
      return yield* fail("No matching JWKS key for id_token");
    }

    const verified = yield* Effect.try({
      try: () => {
        const key = crypto.createPublicKey({
          key: jwk as crypto.JsonWebKeyInput["key"],
          format: "jwk",
        });
        const signingInput = Buffer.from(`${headerSeg}.${payloadSeg}`);
        const signature = Buffer.from(signatureSeg, "base64url");
        if (alg === "RS256") {
          return crypto.verify("sha256", signingInput, key, signature);
        }
        if (alg === "ES256") {
          return crypto.verify(
            "sha256",
            signingInput,
            { key, dsaEncoding: "ieee-p1363" },
            signature,
          );
        }
        return crypto.verify(null, signingInput, key, signature);
      },
      catch: (cause) =>
        new OAuthProviderError({
          message: "id_token signature verification failed",
          provider: params.provider,
          cause,
        }),
    });
    if (!verified) {
      return yield* fail("Invalid id_token signature");
    }

    if (params.issuer !== undefined && payload["iss"] !== params.issuer) {
      return yield* fail("id_token issuer mismatch");
    }
    if (params.audience !== undefined) {
      const aud = payload["aud"];
      const ok = aud === params.audience || (Array.isArray(aud) && aud.includes(params.audience));
      if (!ok) {
        return yield* fail("id_token audience mismatch");
      }
    }
    const nowSec = (params.now ?? Date.now()) / 1000;
    if (typeof payload["exp"] === "number" && nowSec > payload["exp"]) {
      return yield* fail("id_token expired");
    }
    if (params.nonce !== undefined && payload["nonce"] !== params.nonce) {
      return yield* fail("id_token nonce mismatch");
    }

    return payload;
  });

/** Map OIDC id_token / userinfo claims to {@link OAuthUserInfo}. */
const claimsToUserInfo = (claims: Record<string, unknown>): OAuthUserInfo => ({
  ...claims,
  id: String(claims["sub"] ?? claims["id"] ?? ""),
  ...(typeof claims["email"] === "string" && { email: claims["email"] }),
  ...(typeof claims["email_verified"] === "boolean" && {
    email_verified: claims["email_verified"],
  }),
  ...(typeof claims["name"] === "string" && { name: claims["name"] }),
  ...(typeof claims["picture"] === "string" && { picture: claims["picture"] }),
});

/**
 * Create an OAuth provider
 */
export const makeOAuthProvider = (
  name: string,
  config: OAuthProviderConfig,
  usePKCE = true,
): OAuthProvider => {
  const mapProfile = config.mapProfile ?? claimsToUserInfo;

  const getUserInfo = (accessToken: string): Effect.Effect<OAuthUserInfo, OAuthProviderError> =>
    Effect.gen(function* () {
      if (!config.userInfoEndpoint) {
        return yield* Effect.fail(
          new OAuthProviderError({
            message: `Provider ${name} does not have a user info endpoint`,
            provider: name,
          }),
        );
      }

      const response = yield* Effect.tryPromise({
        try: () =>
          fetch(config.userInfoEndpoint!, {
            method: config.userInfoMethod ?? "GET",
            headers: {
              Authorization: `Bearer ${accessToken}`,
              Accept: "application/json",
              ...config.userInfoHeaders,
            },
          }),
        catch: (cause) =>
          new OAuthProviderError({
            message: `Failed to get user info from ${name}`,
            provider: name,
            cause,
          }),
      });

      if (!response.ok) {
        const errorText = yield* Effect.promise(() => response.text());
        return yield* Effect.fail(
          new OAuthProviderError({
            message: `User info request failed: ${errorText}`,
            provider: name,
          }),
        );
      }

      const data = (yield* Effect.promise(() => response.json())) as Record<string, unknown>;

      return mapProfile(data);
    });

  return {
    name,
    config,

    generateAuthorizationUrl: (customScopes?: readonly string[]) =>
      Effect.gen(function* () {
        const stateStore = yield* OAuthStateStore;
        const state = yield* generateState();

        // Generate PKCE if enabled
        const pkce = usePKCE ? yield* generatePKCE() : undefined;
        // OIDC id_token flows carry a nonce for replay protection.
        const nonce = config.getUserInfoFromIdToken ? yield* generateNonce() : undefined;

        // Create state entry
        const stateEntry: OAuthState = {
          state,
          provider: name,
          ...(pkce?.codeVerifier && { codeVerifier: pkce.codeVerifier }),
          ...(nonce && { nonce }),
          createdAt: Date.now(),
          expiresAt: Date.now() + 10 * 60 * 1000, // 10 minutes
        };

        yield* stateStore.create(stateEntry);

        // Build authorization URL
        const clientIdParam = config.clientIdParam ?? "client_id";
        const scopes = customScopes ?? config.scopes;
        const params = new URLSearchParams({
          [clientIdParam]: config.clientId,
          redirect_uri: config.redirectUri,
          response_type: "code",
          scope: scopes.join(" "),
          state,
        });

        if (pkce) {
          params.set("code_challenge", pkce.codeChallenge);
          params.set("code_challenge_method", "S256");
        }
        if (nonce) {
          params.set("nonce", nonce);
        }
        for (const [key, value] of Object.entries(config.authorizationParams ?? {})) {
          params.set(key, value);
        }

        const url = `${config.authorizationEndpoint}?${params.toString()}`;

        return {
          url,
          state,
          ...(pkce?.codeVerifier && { codeVerifier: pkce.codeVerifier }),
        } satisfies AuthorizationUrlResult;
      }),

    exchangeCode: (code: string, codeVerifier?: string) =>
      Effect.gen(function* () {
        const useBasic = config.tokenAuthMethod === "basic";
        const params = new URLSearchParams({
          [config.clientIdParam ?? "client_id"]: config.clientId,
          code,
          grant_type: "authorization_code",
          redirect_uri: config.redirectUri,
        });
        if (!useBasic) {
          params.set("client_secret", Redacted.value(config.clientSecret));
        }

        if (codeVerifier) {
          params.set("code_verifier", codeVerifier);
        }

        const response = yield* Effect.tryPromise({
          try: () =>
            fetch(config.tokenEndpoint, {
              method: "POST",
              headers: {
                "Content-Type": "application/x-www-form-urlencoded",
                Accept: "application/json",
                ...(useBasic && {
                  Authorization: `Basic ${Buffer.from(
                    `${config.clientId}:${Redacted.value(config.clientSecret)}`,
                  ).toString("base64")}`,
                }),
              },
              body: params.toString(),
            }),
          catch: (cause) =>
            new OAuthProviderError({
              message: `Failed to exchange code with ${name}`,
              provider: name,
              cause,
            }),
        });

        if (!response.ok) {
          const errorText = yield* Effect.promise(() => response.text());
          return yield* Effect.fail(
            new OAuthProviderError({
              message: `Token exchange failed: ${errorText}`,
              provider: name,
            }),
          );
        }

        const data = (yield* Effect.promise(() => response.json())) as OAuthTokenResponse;

        return data;
      }),

    getUserInfo,

    getProfile: (tokens, options) =>
      Effect.gen(function* () {
        if (config.getUserInfoFromIdToken) {
          if (!tokens.id_token) {
            return yield* Effect.fail(
              new OAuthProviderError({
                message: `Provider ${name} did not return an id_token`,
                provider: name,
              }),
            );
          }
          if (!config.jwksEndpoint) {
            return yield* Effect.fail(
              new OAuthProviderError({
                message: `Provider ${name} is missing a jwksEndpoint for id_token verification`,
                provider: name,
              }),
            );
          }
          const claims = yield* verifyIdToken(tokens.id_token, {
            provider: name,
            jwksEndpoint: config.jwksEndpoint,
            ...(config.issuer !== undefined && { issuer: config.issuer }),
            audience: config.clientId,
            ...(options?.expectedNonce !== undefined && { nonce: options.expectedNonce }),
          });
          return mapProfile(claims);
        }

        return yield* getUserInfo(tokens.access_token);
      }),
  };
};

/**
 * OAuth service for managing OAuth flows
 */
export interface OAuthServiceShape {
  readonly generateAuthorizationUrl: (
    provider: string,
    options?: { scopes?: readonly string[]; returnTo?: string },
  ) => Effect.Effect<AuthorizationUrlResult, AuthError | OAuthProviderError, OAuthStateStore>;

  readonly handleCallback: (
    state: string,
    code: string,
    options?: { linkToUserId?: string },
  ) => Effect.Effect<
    OAuthCallbackResult,
    AuthError | OAuthProviderError | OAuthStateNotFoundError | OAuthStateExpiredError,
    OAuthStateStore | OAuthAccountStore
  >;

  /**
   * Complete OAuth sign-in: verifies the callback, resolves or creates the
   * user (auto-linking to an existing user when the provider reports a
   * verified email, unless disabled), links the account, and issues a session.
   *
   * This is the recommended high-level entrypoint; use {@link handleCallback}
   * only when managing users yourself.
   */
  readonly signInWithCallback: (
    state: string,
    code: string,
  ) => Effect.Effect<
    OAuthSignInResult,
    | AuthError
    | OAuthProviderError
    | OAuthStateNotFoundError
    | OAuthStateExpiredError
    | OAuthAccountNotLinkedError
    | OAuthMissingEmailError
    | UserNotFoundError
    | HookError,
    OAuthStateStore | OAuthAccountStore | OAuthUserStore | SessionManager | Hooks
  >;

  readonly linkAccount: (
    userId: string,
    provider: string,
    code: string,
    state: string,
  ) => Effect.Effect<
    OAuthAccount,
    | AuthError
    | OAuthProviderError
    | OAuthStateNotFoundError
    | OAuthStateExpiredError
    | OAuthAccountConflictError,
    OAuthStateStore | OAuthAccountStore
  >;

  readonly unlinkAccount: (
    userId: string,
    provider: string,
  ) => Effect.Effect<void, AuthError | OAuthAccountNotFoundError, OAuthAccountStore>;

  readonly refreshAccessToken: (
    userId: string,
    provider: string,
  ) => Effect.Effect<
    string,
    AuthError | OAuthProviderError | OAuthAccountNotFoundError | OAuthNoRefreshTokenError,
    OAuthAccountStore
  >;
}

export class OAuthService extends Context.Service<OAuthService, OAuthServiceShape>()(
  "@effect-auth/OAuthService",
) {
  /**
   * Construct a Layer providing this service.
   */
  static readonly layer = (
    providers: Record<string, OAuthProvider>,
    options: OAuthServiceOptions = {},
  ) => Layer.effect(OAuthService, makeOAuthService(providers, options));
}

/**
 * Effect `Config` for {@link OAuthServiceOptions}.
 *
 * Optional env vars: `OAUTH_AUTO_LINK_BY_VERIFIED_EMAIL`, `OAUTH_ENCRYPT_TOKENS_SECRET`.
 */
export const oauthServiceOptionsConfig = Config.all({
  autoLinkByVerifiedEmail: Config.boolean("OAUTH_AUTO_LINK_BY_VERIFIED_EMAIL").pipe(
    Config.withDefault(true),
  ),
  encryptTokens: Config.redacted("OAUTH_ENCRYPT_TOKENS_SECRET").pipe(
    Config.map((secret) => ({ secret }) as const),
    Config.orElse(() => Config.succeed(undefined)),
  ),
});

/**
 * Options controlling {@link OAuthServiceShape} behaviour.
 */
export interface OAuthServiceOptions {
  /**
   * When a new OAuth account arrives with a provider-verified email that
   * matches an existing user, link the account to that user instead of
   * creating a new one. Defaults to `true`. Only ever applies when the
   * provider reports `email_verified: true`.
   */
  readonly autoLinkByVerifiedEmail?: boolean;
  /**
   * Opt-in encryption-at-rest for `accessToken` and `refreshToken` fields
   * before they are handed to the account store. **Disabled by default** —
   * when omitted, tokens are stored as plaintext and the database / store is
   * solely responsible for protecting them.
   *
   * Pass `{ secret }` to use the built-in AES-256-GCM cipher (key derived
   * from the secret string with SHA-256, random IV per value, GCM auth-tag for
   * integrity). Pass `{ cipher }` to supply a custom {@link TokenCipher}
   * (envelope encryption, HSM-backed keys, etc.).
   *
   * **Recommended for production** when tokens are persisted in a plain
   * relational database or any store that does not encrypt at the column level.
   * Rotation requires re-encrypting every stored token with the new key.
   */
  readonly encryptTokens?:
    | { readonly secret: Redacted.Redacted<string> }
    | { readonly cipher: TokenCipher };
}

/**
 * Create an OAuth service with configured providers
 */
export const makeOAuthService = (
  providers: Record<string, OAuthProvider>,
  options: OAuthServiceOptions = {},
): Effect.Effect<OAuthServiceShape, never> => {
  const autoLinkByVerifiedEmail = options.autoLinkByVerifiedEmail ?? true;

  const cipher: TokenCipher | null = options.encryptTokens
    ? "cipher" in options.encryptTokens
      ? options.encryptTokens.cipher
      : makeAes256GcmCipher(Redacted.value(options.encryptTokens.secret))
    : null;

  const encryptAccount = (account: OAuthAccount): Effect.Effect<OAuthAccount, AuthError> => {
    if (cipher === null) return Effect.succeed(account);
    return Effect.gen(function* () {
      const accessToken = yield* cipher.encrypt(account.accessToken);
      const refreshToken =
        account.refreshToken !== undefined
          ? yield* cipher.encrypt(account.refreshToken)
          : undefined;
      return {
        ...account,
        accessToken,
        ...(refreshToken !== undefined && { refreshToken }),
      };
    });
  };

  const decryptAccount = (account: OAuthAccount): Effect.Effect<OAuthAccount, AuthError> => {
    if (cipher === null) return Effect.succeed(account);
    return Effect.gen(function* () {
      const accessToken = yield* cipher.decrypt(account.accessToken);
      const refreshToken =
        account.refreshToken !== undefined
          ? yield* cipher.decrypt(account.refreshToken)
          : undefined;
      return {
        ...account,
        accessToken,
        ...(refreshToken !== undefined && { refreshToken }),
      };
    });
  };

  /**
   * Shared callback plumbing: verify + consume state, exchange the code and
   * fetch the provider profile.
   */
  const resolveCallback = (state: string, code: string) =>
    Effect.gen(function* () {
      const stateStore = yield* OAuthStateStore;

      const stateEntry = yield* stateStore.get(state);
      if (stateEntry === null) {
        return yield* new OAuthStateNotFoundError({
          message: "OAuth state not found or expired",
          state,
        });
      }

      if (Date.now() > stateEntry.expiresAt) {
        yield* stateStore.delete(state);
        return yield* new OAuthStateExpiredError({
          message: "OAuth state expired",
          state,
        });
      }

      const providerInstance = providers[stateEntry.provider];
      if (!providerInstance) {
        return yield* new OAuthProviderError({
          message: `Provider ${stateEntry.provider} not found`,
          provider: stateEntry.provider,
        });
      }

      const tokens = yield* providerInstance.exchangeCode(code, stateEntry.codeVerifier);
      const userInfo = yield* providerInstance.getProfile(tokens, {
        ...(stateEntry.nonce !== undefined && { expectedNonce: stateEntry.nonce }),
      });

      yield* stateStore.delete(state);

      return { stateEntry, tokens, userInfo };
    });

  return Effect.sync(
    (): OAuthServiceShape => ({
      generateAuthorizationUrl: (provider, options) =>
        Effect.gen(function* () {
          const providerInstance = providers[provider];
          if (!providerInstance) {
            return yield* Effect.fail(
              new OAuthProviderError({
                message: `Provider ${provider} not found`,
                provider,
              }),
            );
          }

          const result = yield* providerInstance.generateAuthorizationUrl(options?.scopes);

          // Update state with returnTo if provided
          if (options?.returnTo) {
            const stateStore = yield* OAuthStateStore;
            const stateEntry = yield* stateStore.get(result.state);
            if (stateEntry === null) {
              return yield* new AuthError({ message: "OAuth state missing after creation" });
            }
            // Delete old state and create new one with returnTo
            yield* stateStore.delete(result.state);
            yield* stateStore.create({
              ...stateEntry,
              returnTo: options.returnTo,
            });
          }

          return result;
        }).pipe(Effect.withSpan("effect-auth.oauth.authorize", { attributes: { provider } })),

      handleCallback: (state, code, options) =>
        Effect.gen(function* () {
          const stateStore = yield* OAuthStateStore;
          const accountStore = yield* OAuthAccountStore;

          // Verify state
          const stateEntry = yield* stateStore.get(state);
          if (stateEntry === null) {
            return yield* new OAuthStateNotFoundError({
              message: "OAuth state not found or expired",
              state,
            });
          }

          // Check expiration
          if (Date.now() > stateEntry.expiresAt) {
            yield* stateStore.delete(state);
            return yield* Effect.fail(
              new OAuthStateExpiredError({
                message: "OAuth state expired",
                state,
              }),
            );
          }

          const providerInstance = providers[stateEntry.provider];
          if (!providerInstance) {
            return yield* Effect.fail(
              new OAuthProviderError({
                message: `Provider ${stateEntry.provider} not found`,
                provider: stateEntry.provider,
              }),
            );
          }

          // Exchange code for tokens
          const tokens = yield* providerInstance.exchangeCode(code, stateEntry.codeVerifier);

          // Get user info (userinfo endpoint or verified OIDC id_token)
          const userInfo = yield* providerInstance.getProfile(tokens, {
            ...(stateEntry.nonce !== undefined && { expectedNonce: stateEntry.nonce }),
          });

          // Clean up state
          yield* stateStore.delete(state);

          // Check if account exists
          const existingAccount = yield* accountStore.get(stateEntry.provider, userInfo.id);

          if (existingAccount) {
            // Update existing account
            const plainExisting = yield* decryptAccount(existingAccount);
            const updatedAccount: OAuthAccount = {
              ...plainExisting,
              accessToken: tokens.access_token,
              ...(tokens.refresh_token && {
                refreshToken: tokens.refresh_token,
              }),
              ...(tokens.expires_in && {
                expiresAt: Date.now() + tokens.expires_in * 1000,
              }),
              updatedAt: Date.now(),
            };
            yield* accountStore.update(yield* encryptAccount(updatedAccount));

            return {
              account: updatedAccount,
              isNewUser: false,
            } satisfies OAuthCallbackResult;
          }

          // Create new account
          // Note: For new accounts without linkToUserId, we create an unlinked account
          // with empty userId. The caller should link it to a user after creating
          // the user record in their database.
          const newAccount: OAuthAccount = {
            id: crypto.randomBytes(16).toString("hex"),
            userId: options?.linkToUserId ?? "",
            provider: stateEntry.provider,
            providerId: userInfo.id,
            ...(userInfo.email && { email: userInfo.email }),
            ...(userInfo.name && { name: userInfo.name }),
            ...(userInfo.picture && { picture: userInfo.picture }),
            accessToken: tokens.access_token,
            ...(tokens.refresh_token && { refreshToken: tokens.refresh_token }),
            ...(tokens.expires_in && {
              expiresAt: Date.now() + tokens.expires_in * 1000,
            }),
            createdAt: Date.now(),
            updatedAt: Date.now(),
          };

          yield* accountStore.create(yield* encryptAccount(newAccount));

          return {
            account: newAccount,
            isNewUser: true,
            ...(options?.linkToUserId
              ? {
                  user: {
                    id: newAccount.userId,
                    ...(userInfo.email && { email: userInfo.email }),
                    ...(userInfo.name && { name: userInfo.name }),
                  },
                }
              : {}),
          } satisfies OAuthCallbackResult;
        }),

      signInWithCallback: (state, code) =>
        Effect.gen(function* () {
          const accountStore = yield* OAuthAccountStore;
          const userStore = yield* OAuthUserStore;
          const sessionManager = yield* SessionManager;

          const { stateEntry, tokens, userInfo } = yield* resolveCallback(state, code);
          const now = Date.now();

          const tokenFields = {
            accessToken: tokens.access_token,
            ...(tokens.refresh_token && { refreshToken: tokens.refresh_token }),
            ...(tokens.expires_in && { expiresAt: now + tokens.expires_in * 1000 }),
          };

          const existingAccount = yield* accountStore.get(stateEntry.provider, userInfo.id);

          if (existingAccount) {
            if (existingAccount.userId === "") {
              return yield* new OAuthAccountNotLinkedError({
                message: `This ${stateEntry.provider} account is not linked to a user`,
                provider: stateEntry.provider,
              });
            }

            const plainExisting = yield* decryptAccount(existingAccount);
            const updatedAccount: OAuthAccount = {
              ...plainExisting,
              ...tokenFields,
              updatedAt: now,
            };
            yield* accountStore.update(yield* encryptAccount(updatedAccount));

            const user = yield* userStore.getUser(updatedAccount.userId);
            const session = yield* sessionManager.createSession(user.id);

            return {
              user,
              account: updatedAccount,
              session,
              isNewUser: false,
              ...(stateEntry.returnTo !== undefined && { returnTo: stateEntry.returnTo }),
            } satisfies OAuthSignInResult;
          }

          // New account: resolve the user by verified email, or create one.
          const email = userInfo.email ? normalizeEmail(userInfo.email) : undefined;
          const emailVerified = userInfo.email_verified === true;

          if (email === undefined) {
            return yield* new OAuthMissingEmailError({
              message: `${stateEntry.provider} did not return an email address for this account`,
              provider: stateEntry.provider,
            });
          }

          let user: Types.User | null = null;
          if (autoLinkByVerifiedEmail && emailVerified) {
            user = yield* userStore.getUserByEmail(email);
          }

          const isNewUser = user === null;
          if (user === null) {
            user = yield* userStore.createUser({
              email,
              emailVerified,
              ...(userInfo.name !== undefined && { name: userInfo.name }),
              ...(userInfo.picture !== undefined && { image: userInfo.picture }),
            });
          }

          const account: OAuthAccount = {
            id: crypto.randomBytes(16).toString("hex"),
            userId: user.id,
            provider: stateEntry.provider,
            providerId: userInfo.id,
            ...(userInfo.email && { email }),
            ...(userInfo.name && { name: userInfo.name }),
            ...(userInfo.picture && { picture: userInfo.picture }),
            ...tokenFields,
            createdAt: now,
            updatedAt: now,
          };
          yield* accountStore.create(yield* encryptAccount(account));

          const session = yield* sessionManager.createSession(user.id);

          return {
            user,
            account,
            session,
            isNewUser,
            ...(stateEntry.returnTo !== undefined && { returnTo: stateEntry.returnTo }),
          } satisfies OAuthSignInResult;
        }).pipe(
          Effect.withSpan("effect-auth.oauth.callback"),
          Effect.tap(() => Obs.recordOAuthCallback("success")),
          Effect.tapError(() => Obs.recordOAuthCallback("failure")),
        ),

      linkAccount: (userId, provider, code, state) =>
        Effect.gen(function* () {
          // Properly implement OAuth flow for account linking
          // This follows the same flow as handleCallback but links to existing user
          const stateStore = yield* OAuthStateStore;
          const accountStore = yield* OAuthAccountStore;

          // Verify state
          const stateEntry = yield* stateStore.get(state);
          if (stateEntry === null) {
            return yield* new OAuthStateNotFoundError({
              message: "OAuth state not found or expired",
              state,
            });
          }

          if (stateEntry.provider !== provider) {
            return yield* Effect.fail(
              new OAuthProviderError({
                message: `State provider mismatch: expected ${provider}, got ${stateEntry.provider}`,
                provider,
              }),
            );
          }

          // Check expiration
          if (Date.now() > stateEntry.expiresAt) {
            yield* stateStore.delete(state);
            return yield* Effect.fail(
              new OAuthStateExpiredError({
                message: "OAuth state expired",
                state,
              }),
            );
          }

          const providerInstance = providers[provider];
          if (!providerInstance) {
            return yield* Effect.fail(
              new OAuthProviderError({
                message: `Provider ${provider} not found`,
                provider,
              }),
            );
          }

          // Exchange code for tokens
          const tokens = yield* providerInstance.exchangeCode(code, stateEntry.codeVerifier);

          // Get user info (userinfo endpoint or verified OIDC id_token)
          const userInfo = yield* providerInstance.getProfile(tokens, {
            ...(stateEntry.nonce !== undefined && { expectedNonce: stateEntry.nonce }),
          });

          // Clean up state
          yield* stateStore.delete(state);

          // Check if this OAuth account is already linked to another user
          const existingAccount = yield* accountStore.get(provider, userInfo.id);

          if (existingAccount && existingAccount.userId !== userId) {
            return yield* Effect.fail(
              new OAuthAccountConflictError({
                message: `This ${provider} account is already linked to another user`,
                provider,
              }),
            );
          }

          // Create or update the account linked to this user
          const account: OAuthAccount = {
            id: existingAccount?.id ?? crypto.randomBytes(16).toString("hex"),
            userId,
            provider,
            providerId: userInfo.id,
            ...(userInfo.email && { email: userInfo.email }),
            ...(userInfo.name && { name: userInfo.name }),
            ...(userInfo.picture && { picture: userInfo.picture }),
            accessToken: tokens.access_token,
            ...(tokens.refresh_token && { refreshToken: tokens.refresh_token }),
            ...(tokens.expires_in && {
              expiresAt: Date.now() + tokens.expires_in * 1000,
            }),
            createdAt: existingAccount?.createdAt ?? Date.now(),
            updatedAt: Date.now(),
          };

          if (existingAccount) {
            yield* accountStore.update(yield* encryptAccount(account));
          } else {
            yield* accountStore.create(yield* encryptAccount(account));
          }

          return account;
        }),

      unlinkAccount: (userId, provider) =>
        Effect.gen(function* () {
          const accountStore = yield* OAuthAccountStore;
          const accounts = yield* accountStore.getByUserId(userId);
          const account = accounts.find((a) => a.provider === provider);

          if (!account) {
            return yield* Effect.fail(
              new OAuthAccountNotFoundError({
                message: `No ${provider} account linked to this user`,
                provider,
              }),
            );
          }

          yield* accountStore.delete(provider, account.providerId);
        }),

      refreshAccessToken: (userId, provider) =>
        Effect.gen(function* () {
          const accountStore = yield* OAuthAccountStore;
          const accounts = yield* accountStore.getByUserId(userId);
          const account = accounts.find((a) => a.provider === provider);

          if (!account) {
            return yield* Effect.fail(
              new OAuthAccountNotFoundError({
                message: `No ${provider} account linked to this user`,
                provider,
              }),
            );
          }
          if (!account.refreshToken) {
            return yield* Effect.fail(
              new OAuthNoRefreshTokenError({
                message: `No refresh token available for ${provider}`,
                provider,
              }),
            );
          }

          const plainAccount = yield* decryptAccount(account);

          const providerInstance = providers[provider];
          if (!providerInstance) {
            return yield* Effect.fail(
              new OAuthProviderError({
                message: `Provider ${provider} not found`,
                provider,
              }),
            );
          }

          // Exchange refresh token for new access token
          const rConfig = providerInstance.config;
          const rUseBasic = rConfig.tokenAuthMethod === "basic";
          const params = new URLSearchParams({
            [rConfig.clientIdParam ?? "client_id"]: rConfig.clientId,
            grant_type: "refresh_token",
            refresh_token: plainAccount.refreshToken!,
          });
          if (!rUseBasic) {
            params.set("client_secret", Redacted.value(rConfig.clientSecret));
          }

          const response = yield* Effect.tryPromise({
            try: () =>
              fetch(rConfig.tokenEndpoint, {
                method: "POST",
                headers: {
                  "Content-Type": "application/x-www-form-urlencoded",
                  ...(rUseBasic && {
                    Authorization: `Basic ${Buffer.from(
                      `${rConfig.clientId}:${Redacted.value(rConfig.clientSecret)}`,
                    ).toString("base64")}`,
                  }),
                },
                body: params.toString(),
              }),
            catch: (cause) =>
              new OAuthProviderError({
                message: `Failed to refresh token for ${provider}`,
                provider,
                cause,
              }),
          });

          if (!response.ok) {
            const errorText = yield* Effect.promise(() => response.text());
            return yield* Effect.fail(
              new OAuthProviderError({
                message: `Token refresh failed: ${errorText}`,
                provider,
              }),
            );
          }

          const data = (yield* Effect.promise(() => response.json())) as OAuthTokenResponse;

          // Update account with new tokens
          const updatedAccount: OAuthAccount = {
            ...plainAccount,
            accessToken: data.access_token,
            ...(data.refresh_token && { refreshToken: data.refresh_token }),
            ...(data.expires_in && {
              expiresAt: Date.now() + data.expires_in * 1000,
            }),
            updatedAt: Date.now(),
          };

          yield* accountStore.update(yield* encryptAccount(updatedAccount));

          return data.access_token;
        }).pipe(
          Effect.withSpan("effect-auth.oauth.refresh", { attributes: { provider } }),
          Effect.tap(() => Obs.recordOAuthRefresh(provider, "success")),
          Effect.tapError(() => Obs.recordOAuthRefresh(provider, "failure")),
        ),
    }),
  );
};

/**
 * Pre-built OAuth providers
 */

export const GoogleProvider = (config: {
  clientId: string;
  clientSecret: Redacted.Redacted<string>;
  redirectUri: string;
}): OAuthProvider =>
  makeOAuthProvider(
    "google",
    {
      ...config,
      authorizationEndpoint: "https://accounts.google.com/o/oauth2/v2/auth",
      tokenEndpoint: "https://oauth2.googleapis.com/token",
      userInfoEndpoint: "https://www.googleapis.com/oauth2/v2/userinfo",
      scopes: ["openid", "email", "profile"],
    },
    true, // Use PKCE
  );

export const GitHubProvider = (config: {
  clientId: string;
  clientSecret: Redacted.Redacted<string>;
  redirectUri: string;
}): OAuthProvider =>
  makeOAuthProvider(
    "github",
    {
      ...config,
      authorizationEndpoint: "https://github.com/login/oauth/authorize",
      tokenEndpoint: "https://github.com/login/oauth/access_token",
      userInfoEndpoint: "https://api.github.com/user",
      scopes: ["user:email"],
    },
    false, // GitHub doesn't support PKCE yet
  );

export const DiscordProvider = (config: {
  clientId: string;
  clientSecret: Redacted.Redacted<string>;
  redirectUri: string;
}): OAuthProvider =>
  makeOAuthProvider(
    "discord",
    {
      ...config,
      authorizationEndpoint: "https://discord.com/api/oauth2/authorize",
      tokenEndpoint: "https://discord.com/api/oauth2/token",
      userInfoEndpoint: "https://discord.com/api/users/@me",
      scopes: ["identify", "email"],
    },
    true, // Use PKCE
  );

export const MicrosoftProvider = (config: {
  clientId: string;
  clientSecret: Redacted.Redacted<string>;
  redirectUri: string;
  tenant?: string;
}): OAuthProvider =>
  makeOAuthProvider(
    "microsoft",
    {
      ...config,
      authorizationEndpoint: `https://login.microsoftonline.com/${config.tenant ?? "common"}/oauth2/v2.0/authorize`,
      tokenEndpoint: `https://login.microsoftonline.com/${config.tenant ?? "common"}/oauth2/v2.0/token`,
      userInfoEndpoint: "https://graph.microsoft.com/v1.0/me",
      scopes: ["openid", "email", "profile"],
    },
    true, // Use PKCE
  );

/** The `{ clientId, clientSecret, redirectUri }` triple every provider needs. */
export interface OAuthClientConfig {
  readonly clientId: string;
  readonly clientSecret: Redacted.Redacted<string>;
  readonly redirectUri: string;
}

/** Coerce a value to `string` — returns `undefined` for non-strings. */
export const str = (v: unknown): string | undefined => (typeof v === "string" ? v : undefined);

/**
 * Safely traverse a nested object by a chain of keys. Returns `undefined`
 * at the first missing or non-object step.
 *
 * @example
 * nested(raw["picture"], "data", "url") // → raw.picture?.data?.url
 */
export const nested = (v: unknown, ...path: string[]): unknown =>
  path.reduce<unknown>(
    (acc, key) =>
      acc && typeof acc === "object" ? (acc as Record<string, unknown>)[key] : undefined,
    v,
  );

/**
 * Build an {@link OAuthUserInfo} from a base record plus normalized identity
 * fields, omitting any that are `undefined` (satisfies
 * `exactOptionalPropertyTypes`).
 *
 * @example
 * profile(raw, { id: raw["id"], email: str(raw["email"]), name: str(raw["name"]) })
 */
export const profile = (
  base: Record<string, unknown>,
  fields: {
    readonly id: unknown;
    readonly email?: string | undefined;
    readonly name?: string | undefined;
    readonly picture?: string | undefined;
    readonly email_verified?: boolean | undefined;
  },
): OAuthUserInfo => ({
  ...base,
  id: String(fields.id ?? ""),
  ...(fields.email !== undefined && { email: fields.email }),
  ...(fields.name !== undefined && { name: fields.name }),
  ...(fields.picture !== undefined && { picture: fields.picture }),
  ...(fields.email_verified !== undefined && { email_verified: fields.email_verified }),
});

/**
 * Profile-mapping helpers for use in custom {@link OAuthProviderConfig.mapProfile}
 * implementations. These are the same utilities used by every built-in provider
 * preset (Facebook, Twitter, Spotify, …), now exported so your own `mapProfile`
 * can be just as terse.
 *
 * @example
 * import { makeOAuthProvider, ProfileMap } from "effect-auth";
 *
 * const LinearProvider = (config: OAuthClientConfig): OAuthProvider =>
 *   makeOAuthProvider("linear", {
 *     ...config,
 *     authorizationEndpoint: "https://linear.app/oauth/authorize",
 *     tokenEndpoint: "https://api.linear.app/oauth/token",
 *     userInfoEndpoint: "https://api.linear.app/graphql",
 *     scopes: ["read"],
 *     mapProfile: (raw) =>
 *       ProfileMap.profile(raw, {
 *         id: raw["id"],
 *         email: ProfileMap.str(raw["email"]),
 *         name: ProfileMap.str(raw["name"]),
 *         picture: ProfileMap.str(ProfileMap.nested(raw["avatarUrl"])),
 *       }),
 *   }, true);
 */
export const ProfileMap = { str, nested, profile } as const;

/**
 * Sign-in with Apple. Apple returns identity only via the OIDC `id_token`
 * (`response_mode=form_post`, `name`/`email` scopes). `clientSecret` must be a
 * signed ES256 JWT — generate it with {@link makeAppleClientSecret}.
 */
export const AppleProvider = (config: OAuthClientConfig): OAuthProvider =>
  makeOAuthProvider(
    "apple",
    {
      ...config,
      authorizationEndpoint: "https://appleid.apple.com/auth/authorize",
      tokenEndpoint: "https://appleid.apple.com/auth/token",
      jwksEndpoint: "https://appleid.apple.com/auth/keys",
      issuer: "https://appleid.apple.com",
      getUserInfoFromIdToken: true,
      scopes: ["name", "email"],
      authorizationParams: { response_mode: "form_post" },
    },
    true,
  );

/**
 * Build the ES256-signed client-secret JWT Apple requires (valid up to 6
 * months; Apple caps `exp` at 15777000s). Pass the result as `clientSecret`
 * to {@link AppleProvider}.
 */
export const makeAppleClientSecret = (params: {
  readonly teamId: string;
  readonly clientId: string;
  readonly keyId: string;
  /** PKCS#8 PEM of the private key downloaded from Apple. */
  readonly privateKey: Redacted.Redacted<string>;
  /** Lifetime in seconds (default 6 months, Apple's maximum). */
  readonly expiresIn?: number;
  readonly now?: number;
}): Effect.Effect<string, OAuthProviderError> =>
  Effect.try({
    try: () => {
      const iat = Math.floor((params.now ?? Date.now()) / 1000);
      const exp = iat + (params.expiresIn ?? 15777000);
      const header = { alg: "ES256", kid: params.keyId, typ: "JWT" };
      const payload = {
        iss: params.teamId,
        iat,
        exp,
        aud: "https://appleid.apple.com",
        sub: params.clientId,
      };
      const encode = (obj: unknown): string =>
        Buffer.from(JSON.stringify(obj), "utf8").toString("base64url");
      const signingInput = `${encode(header)}.${encode(payload)}`;
      const key = crypto.createPrivateKey(Redacted.value(params.privateKey));
      const signature = crypto
        .sign("sha256", Buffer.from(signingInput), { key, dsaEncoding: "ieee-p1363" })
        .toString("base64url");
      return `${signingInput}.${signature}`;
    },
    catch: (cause) =>
      new OAuthProviderError({
        message: "Failed to sign Apple client secret",
        provider: "apple",
        cause,
      }),
  });

/** Facebook Login (Graph API userinfo; `picture` is nested under `data.url`). */
export const FacebookProvider = (config: OAuthClientConfig): OAuthProvider =>
  makeOAuthProvider(
    "facebook",
    {
      ...config,
      authorizationEndpoint: "https://www.facebook.com/v18.0/dialog/oauth",
      tokenEndpoint: "https://graph.facebook.com/v18.0/oauth/access_token",
      userInfoEndpoint: "https://graph.facebook.com/me?fields=id,name,email,picture",
      scopes: ["email", "public_profile"],
      mapProfile: (raw) =>
        profile(raw, {
          id: raw["id"],
          email: str(raw["email"]),
          name: str(raw["name"]),
          picture: str(nested(raw["picture"], "data", "url")),
        }),
    },
    false,
  );

/** X/Twitter OAuth2 (PKCE + Basic auth required; email needs elevated access). */
export const TwitterProvider = (config: OAuthClientConfig): OAuthProvider =>
  makeOAuthProvider(
    "twitter",
    {
      ...config,
      authorizationEndpoint: "https://twitter.com/i/oauth2/authorize",
      tokenEndpoint: "https://api.twitter.com/2/oauth2/token",
      userInfoEndpoint: "https://api.twitter.com/2/users/me?user.fields=profile_image_url",
      scopes: ["users.read", "tweet.read"],
      tokenAuthMethod: "basic",
      mapProfile: (raw) => {
        const data = (raw["data"] ?? raw) as Record<string, unknown>;
        return profile(data, {
          id: data["id"],
          name: str(data["name"]),
          picture: str(data["profile_image_url"]),
        });
      },
    },
    true,
  );

/** LinkedIn (OpenID Connect userinfo). */
export const LinkedInProvider = (config: OAuthClientConfig): OAuthProvider =>
  makeOAuthProvider(
    "linkedin",
    {
      ...config,
      authorizationEndpoint: "https://www.linkedin.com/oauth/v2/authorization",
      tokenEndpoint: "https://www.linkedin.com/oauth/v2/accessToken",
      userInfoEndpoint: "https://api.linkedin.com/v2/userinfo",
      scopes: ["openid", "profile", "email"],
    },
    false,
  );

/** Twitch (OpenID Connect userinfo). */
export const TwitchProvider = (config: OAuthClientConfig): OAuthProvider =>
  makeOAuthProvider(
    "twitch",
    {
      ...config,
      authorizationEndpoint: "https://id.twitch.tv/oauth2/authorize",
      tokenEndpoint: "https://id.twitch.tv/oauth2/token",
      userInfoEndpoint: "https://id.twitch.tv/oauth2/userinfo",
      scopes: ["openid", "user:read:email"],
    },
    false,
  );

/** Spotify (Basic auth token exchange; `images[0].url`, `display_name`). */
export const SpotifyProvider = (config: OAuthClientConfig): OAuthProvider =>
  makeOAuthProvider(
    "spotify",
    {
      ...config,
      authorizationEndpoint: "https://accounts.spotify.com/authorize",
      tokenEndpoint: "https://accounts.spotify.com/api/token",
      userInfoEndpoint: "https://api.spotify.com/v1/me",
      scopes: ["user-read-email", "user-read-private"],
      tokenAuthMethod: "basic",
      mapProfile: (raw) => {
        const images = raw["images"];
        const picture = Array.isArray(images) ? str(nested(images[0], "url")) : undefined;
        return profile(raw, {
          id: raw["id"],
          email: str(raw["email"]),
          name: str(raw["display_name"]),
          picture,
        });
      },
    },
    false,
  );

/** GitLab (`gitlab.com` by default; pass `baseUrl` for self-hosted). */
export const GitLabProvider = (
  config: OAuthClientConfig & { readonly baseUrl?: string },
): OAuthProvider => {
  const base = (config.baseUrl ?? "https://gitlab.com").replace(/\/$/, "");
  return makeOAuthProvider(
    "gitlab",
    {
      clientId: config.clientId,
      clientSecret: config.clientSecret,
      redirectUri: config.redirectUri,
      authorizationEndpoint: `${base}/oauth/authorize`,
      tokenEndpoint: `${base}/oauth/token`,
      userInfoEndpoint: `${base}/api/v4/user`,
      scopes: ["read_user"],
      mapProfile: (raw) =>
        profile(raw, {
          id: raw["id"],
          email: str(raw["email"]),
          name: str(raw["name"]),
          picture: str(raw["avatar_url"]),
        }),
    },
    true,
  );
};

/** Reddit (Basic auth; `identity` scope; no email; `duration=permanent`). */
export const RedditProvider = (config: OAuthClientConfig): OAuthProvider =>
  makeOAuthProvider(
    "reddit",
    {
      ...config,
      authorizationEndpoint: "https://www.reddit.com/api/v1/authorize",
      tokenEndpoint: "https://www.reddit.com/api/v1/access_token",
      userInfoEndpoint: "https://oauth.reddit.com/api/v1/me",
      scopes: ["identity"],
      tokenAuthMethod: "basic",
      authorizationParams: { duration: "permanent" },
      mapProfile: (raw) =>
        profile(raw, {
          id: raw["id"],
          name: str(raw["name"]),
          picture: str(raw["icon_img"]),
        }),
    },
    false,
  );

/** Dropbox (POST userinfo; `token_access_type=offline` for refresh tokens). */
export const DropboxProvider = (config: OAuthClientConfig): OAuthProvider =>
  makeOAuthProvider(
    "dropbox",
    {
      ...config,
      authorizationEndpoint: "https://www.dropbox.com/oauth2/authorize",
      tokenEndpoint: "https://api.dropboxapi.com/oauth2/token",
      userInfoEndpoint: "https://api.dropboxapi.com/2/users/get_current_account",
      userInfoMethod: "POST",
      scopes: ["account_info.read"],
      authorizationParams: { token_access_type: "offline" },
      mapProfile: (raw) =>
        profile(raw, {
          id: raw["account_id"],
          email: str(raw["email"]),
          name: str(nested(raw["name"], "display_name")),
          picture: str(raw["profile_photo_url"]),
        }),
    },
    true,
  );

/** Notion (Basic auth; profile via `/v1/users/me` bot owner). */
export const NotionProvider = (config: OAuthClientConfig): OAuthProvider =>
  makeOAuthProvider(
    "notion",
    {
      ...config,
      authorizationEndpoint: "https://api.notion.com/v1/oauth/authorize",
      tokenEndpoint: "https://api.notion.com/v1/oauth/token",
      userInfoEndpoint: "https://api.notion.com/v1/users/me",
      userInfoHeaders: { "Notion-Version": "2022-06-28" },
      scopes: [],
      tokenAuthMethod: "basic",
      authorizationParams: { owner: "user" },
      mapProfile: (raw) => {
        const user = (nested(raw, "bot", "owner", "user") ?? raw) as Record<string, unknown>;
        return profile(raw, {
          id: user["id"] ?? raw["id"],
          email: str(nested(user, "person", "email")),
          name: str(user["name"]),
          picture: str(user["avatar_url"]),
        });
      },
    },
    false,
  );

/** Slack (Sign in with Slack / OpenID Connect). */
export const SlackProvider = (config: OAuthClientConfig): OAuthProvider =>
  makeOAuthProvider(
    "slack",
    {
      ...config,
      authorizationEndpoint: "https://slack.com/openid/connect/authorize",
      tokenEndpoint: "https://slack.com/api/openid.connect.token",
      userInfoEndpoint: "https://slack.com/api/openid.connect.userInfo",
      scopes: ["openid", "email", "profile"],
    },
    false,
  );

/** Zoom (Basic auth; `first_name`/`last_name`, `pic_url`). */
export const ZoomProvider = (config: OAuthClientConfig): OAuthProvider =>
  makeOAuthProvider(
    "zoom",
    {
      ...config,
      authorizationEndpoint: "https://zoom.us/oauth/authorize",
      tokenEndpoint: "https://zoom.us/oauth/token",
      userInfoEndpoint: "https://api.zoom.us/v2/users/me",
      scopes: ["user:read"],
      tokenAuthMethod: "basic",
      mapProfile: (raw) => {
        const name = [str(raw["first_name"]), str(raw["last_name"])].filter(Boolean).join(" ");
        return profile(raw, {
          id: raw["id"],
          email: str(raw["email"]),
          name: name === "" ? undefined : name,
          picture: str(raw["pic_url"]),
        });
      },
    },
    true,
  );

/** TikTok (uses `client_key`; PKCE; profile under `data.user`). */
export const TikTokProvider = (config: OAuthClientConfig): OAuthProvider =>
  makeOAuthProvider(
    "tiktok",
    {
      ...config,
      clientIdParam: "client_key",
      authorizationEndpoint: "https://www.tiktok.com/v2/auth/authorize/",
      tokenEndpoint: "https://open.tiktokapis.com/v2/oauth/token/",
      userInfoEndpoint:
        "https://open.tiktokapis.com/v2/user/info/?fields=open_id,display_name,avatar_url",
      scopes: ["user.info.basic"],
      mapProfile: (raw) => {
        const user = (nested(raw, "data", "user") ?? raw) as Record<string, unknown>;
        return profile(user, {
          id: user["open_id"] ?? user["id"],
          name: str(user["display_name"]),
          picture: str(user["avatar_url"]),
        });
      },
    },
    true,
  );

/** Roblox (OpenID Connect; PKCE required). */
export const RobloxProvider = (config: OAuthClientConfig): OAuthProvider =>
  makeOAuthProvider(
    "roblox",
    {
      ...config,
      authorizationEndpoint: "https://apis.roblox.com/oauth/v1/authorize",
      tokenEndpoint: "https://apis.roblox.com/oauth/v1/token",
      userInfoEndpoint: "https://apis.roblox.com/oauth/v1/userinfo",
      scopes: ["openid", "profile"],
    },
    true,
  );

/** Kick (PKCE required; profile under `data[0]`). */
export const KickProvider = (config: OAuthClientConfig): OAuthProvider =>
  makeOAuthProvider(
    "kick",
    {
      ...config,
      authorizationEndpoint: "https://id.kick.com/oauth/authorize",
      tokenEndpoint: "https://id.kick.com/oauth/token",
      userInfoEndpoint: "https://api.kick.com/public/v1/users",
      scopes: ["user:read"],
      mapProfile: (raw) => {
        const data = raw["data"];
        const user = (Array.isArray(data) ? data[0] : raw) as Record<string, unknown>;
        return profile(user, {
          id: user["user_id"] ?? user["id"],
          email: str(user["email"]),
          name: str(user["name"]),
          picture: str(user["profile_picture"]),
        });
      },
    },
    true,
  );

/** Hugging Face (OpenID Connect; PKCE). */
export const HuggingFaceProvider = (config: OAuthClientConfig): OAuthProvider =>
  makeOAuthProvider(
    "huggingface",
    {
      ...config,
      authorizationEndpoint: "https://huggingface.co/oauth/authorize",
      tokenEndpoint: "https://huggingface.co/oauth/token",
      userInfoEndpoint: "https://huggingface.co/oauth/userinfo",
      scopes: ["openid", "profile", "email"],
    },
    true,
  );

/**
 * Endpoint set resolved from an OpenID Connect discovery document, in the
 * shape {@link OAuthProviderConfig} expects.
 */
export interface DiscoveredEndpoints {
  readonly issuer: string;
  readonly authorizationEndpoint: string;
  readonly tokenEndpoint: string;
  readonly userInfoEndpoint?: string;
  readonly jwksEndpoint?: string;
}

/**
 * Populate a provider's endpoints from an issuer's
 * `/.well-known/openid-configuration`. Spread the result into a
 * {@link makeOAuthProvider} config to build a generic OIDC provider.
 */
export const discoverOAuthEndpoints = (
  issuerUrl: string,
): Effect.Effect<DiscoveredEndpoints, OAuthProviderError> =>
  Effect.gen(function* () {
    const base = issuerUrl.replace(/\/$/, "");
    const url = `${base}/.well-known/openid-configuration`;
    const response = yield* Effect.tryPromise({
      try: () => fetch(url, { headers: { Accept: "application/json" } }),
      catch: (cause) =>
        new OAuthProviderError({
          message: `Failed to fetch OIDC discovery document from ${url}`,
          provider: issuerUrl,
          cause,
        }),
    });
    if (!response.ok) {
      return yield* Effect.fail(
        new OAuthProviderError({
          message: `OIDC discovery request failed with status ${response.status}`,
          provider: issuerUrl,
        }),
      );
    }
    const doc = (yield* Effect.promise(() => response.json())) as Record<string, unknown>;
    const authorization = str(doc["authorization_endpoint"]);
    const token = str(doc["token_endpoint"]);
    if (!authorization || !token) {
      return yield* Effect.fail(
        new OAuthProviderError({
          message: "OIDC discovery document is missing authorization_endpoint or token_endpoint",
          provider: issuerUrl,
        }),
      );
    }
    const userInfo = str(doc["userinfo_endpoint"]);
    const jwks = str(doc["jwks_uri"]);
    return {
      issuer: str(doc["issuer"]) ?? base,
      authorizationEndpoint: authorization,
      tokenEndpoint: token,
      ...(userInfo !== undefined && { userInfoEndpoint: userInfo }),
      ...(jwks !== undefined && { jwksEndpoint: jwks }),
    } satisfies DiscoveredEndpoints;
  });
