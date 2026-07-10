/**
 * OIDC Provider — act as an OpenID Connect identity provider.
 *
 * Mirrors better-auth's `oidc-provider` plugin: register client applications,
 * run the authorization-code flow (with PKCE), handle consent, and issue
 * opaque access/refresh tokens plus signed `id_token`s so third-party apps can
 * federate sign-in to this server.
 *
 * The `id_token` is signed with the {@link module:jwt} `JWTService`, sharing
 * its signing keys — the JWKS published at `/.well-known/jwks.json` (or
 * `GET /jwks`) verifies both plain user JWTs and OIDC `id_token`s.
 *
 * Secrets at rest: client secrets, authorization codes, and access/refresh
 * tokens are stored only as sha256 hex digests — lookups by exact digest are
 * inherently timing-safe, and secret comparison re-hashes both sides before a
 * `crypto.timingSafeEqual`.
 *
 * @module oidc-provider
 */
import { Context, Crypto, Data, Effect, Layer, Redacted } from "effect";
import { AuthError } from "./Errors.ts";
import { JWTService } from "./JWT.ts";
import * as Obs from "./Observability.ts";
import * as PlatformCrypto from "./PlatformCrypto.ts";
import { UserStore } from "./session/UserStore.ts";
import { constantTimeHashEqual, hashToken } from "./TokenHash.ts";
import type * as Types from "./Types.ts";

/** Failure to register a client or process an authorization request. */
export class OIDCProviderError extends Data.TaggedError("OIDCProviderError")<{
  readonly message: string;
  readonly cause?: unknown;
}> {}

/**
 * Token endpoint failure carrying an RFC 6749 error code
 * (`invalid_request`, `invalid_client`, `invalid_grant`,
 * `unsupported_grant_type`, `invalid_scope`, `server_error`).
 */
export class OIDCTokenError extends Data.TaggedError("OIDCTokenError")<{
  readonly error: string;
  readonly description?: string;
}> {}

// -----------------------------------------------------------------------------
// Records + stores
// -----------------------------------------------------------------------------

/** A registered OAuth2/OIDC client application. */
export interface OIDCClient {
  readonly clientId: string;
  /** sha256 hex digest of the client secret — absent for public (native) clients. */
  readonly clientSecretHash?: string;
  readonly name: string;
  /** Exact-match redirect URIs (no wildcards). */
  readonly redirectUris: readonly string[];
  /** `web` = confidential (has a secret); `native` = public (PKCE required). */
  readonly type: "web" | "native";
  /** Skip the consent screen for this client (first-party apps). */
  readonly skipConsent: boolean;
  readonly disabled: boolean;
  readonly metadata: Record<string, unknown>;
  /** User id of the admin who registered the client. */
  readonly userId?: string;
  /** Epoch milliseconds. */
  readonly createdAt: number;
  readonly updatedAt: number;
}

/** Persistent registry of OIDC clients. */
export class OIDCClientStore extends Context.Service<
  OIDCClientStore,
  {
    readonly create: (client: OIDCClient) => Effect.Effect<OIDCClient, AuthError>;
    readonly getByClientId: (clientId: string) => Effect.Effect<OIDCClient | null, AuthError>;
    readonly update: (client: OIDCClient) => Effect.Effect<OIDCClient, AuthError>;
    readonly delete: (clientId: string) => Effect.Effect<void, AuthError>;
    readonly list: () => Effect.Effect<ReadonlyArray<OIDCClient>, AuthError>;
  }
>()("@effect-auth/OIDCClientStore") {}

/**
 * A short-lived authorization artifact: either an issued authorization code
 * (`kind: "authorization_code"`) or a pending consent request
 * (`kind: "pending_consent"`), keyed by the sha256 hex digest of the
 * user-visible value.
 */
export interface OIDCAuthorizationCode {
  /** sha256 hex digest of the code — never the plaintext. */
  readonly codeHash: string;
  readonly kind: "authorization_code" | "pending_consent";
  readonly clientId: string;
  readonly userId: string;
  readonly scopes: readonly string[];
  readonly redirectUri: string;
  readonly state?: string;
  readonly codeChallenge?: string;
  readonly codeChallengeMethod?: "S256";
  readonly nonce?: string;
  /** Epoch milliseconds. */
  readonly expiresAt: number;
  readonly createdAt: number;
}

/** Ephemeral store for authorization codes and pending consent requests. */
export class OIDCCodeStore extends Context.Service<
  OIDCCodeStore,
  {
    readonly create: (
      code: OIDCAuthorizationCode,
    ) => Effect.Effect<OIDCAuthorizationCode, AuthError>;
    readonly get: (codeHash: string) => Effect.Effect<OIDCAuthorizationCode | null, AuthError>;
    readonly delete: (codeHash: string) => Effect.Effect<void, AuthError>;
  }
>()("@effect-auth/OIDCCodeStore") {}

/** An issued opaque token, keyed by the sha256 hex digest of its value. */
export interface OIDCToken {
  /** sha256 hex digest of the token — never the plaintext. */
  readonly tokenHash: string;
  readonly kind: "access" | "refresh";
  readonly clientId: string;
  readonly userId: string;
  readonly scopes: readonly string[];
  /** Epoch milliseconds. */
  readonly expiresAt: number;
  readonly createdAt: number;
  /** Refresh-token rotation family (all tokens issued from the same authorization_code grant). */
  readonly familyId?: string;
  /** Absolute (non-sliding) expiry for the whole refresh family. Epoch milliseconds. */
  readonly absoluteExpiresAt?: number;
}

/** Store for issued access and refresh tokens. */
export class OIDCTokenStore extends Context.Service<
  OIDCTokenStore,
  {
    readonly create: (token: OIDCToken) => Effect.Effect<OIDCToken, AuthError>;
    readonly get: (tokenHash: string) => Effect.Effect<OIDCToken | null, AuthError>;
    readonly delete: (tokenHash: string) => Effect.Effect<void, AuthError>;
    /** Optional: list all tokens belonging to a rotation family. Used for reuse-detection revocation. */
    readonly listByFamily?: (
      familyId: string,
    ) => Effect.Effect<ReadonlyArray<OIDCToken>, AuthError>;
  }
>()("@effect-auth/OIDCTokenStore") {}

/** A user's recorded consent for a client (the union of granted scopes). */
export interface OIDCConsent {
  readonly userId: string;
  readonly clientId: string;
  readonly scopes: readonly string[];
  /** Epoch milliseconds. */
  readonly createdAt: number;
  readonly updatedAt: number;
}

/** Store for recorded user consents. */
export class OIDCConsentStore extends Context.Service<
  OIDCConsentStore,
  {
    readonly get: (
      userId: string,
      clientId: string,
    ) => Effect.Effect<OIDCConsent | null, AuthError>;
    readonly upsert: (consent: OIDCConsent) => Effect.Effect<OIDCConsent, AuthError>;
    readonly delete: (userId: string, clientId: string) => Effect.Effect<void, AuthError>;
  }
>()("@effect-auth/OIDCConsentStore") {}

// -----------------------------------------------------------------------------
// Service types
// -----------------------------------------------------------------------------

/** Input to {@link OIDCProviderService.registerClient}. */
export interface RegisterOIDCClientInput {
  readonly name: string;
  readonly redirectUris: readonly string[];
  /** Default `"web"` (confidential — a secret is generated). */
  readonly type?: "web" | "native";
  /** Default `false`. */
  readonly skipConsent?: boolean;
  readonly metadata?: Record<string, unknown>;
}

/** Result of registering a client: the plaintext secret is shown exactly once. */
export interface RegisteredOIDCClient {
  readonly client: OIDCClient;
  /** Only present for `web` (confidential) clients. */
  readonly clientSecret?: string;
}

/** Fields updatable via {@link OIDCProviderService.updateClient}. */
export interface UpdateOIDCClientInput {
  readonly name?: string;
  readonly redirectUris?: readonly string[];
  readonly skipConsent?: boolean;
  readonly disabled?: boolean;
  readonly metadata?: Record<string, unknown>;
}

/** A parsed `GET /oauth2/authorize` request (snake_case per RFC 6749). */
export interface OIDCAuthorizeRequest {
  readonly responseType: string;
  readonly clientId: string;
  readonly redirectUri: string;
  /** Space-separated scope list. */
  readonly scope?: string;
  readonly state?: string;
  readonly codeChallenge?: string;
  readonly codeChallengeMethod?: string;
  readonly nonce?: string;
  /** `"consent"` forces the consent screen even when previously granted. */
  readonly prompt?: string;
}

/**
 * Outcome of an authorization request. All variants carry a `redirectTo` URL
 * the HTTP layer answers with a `302`:
 *
 * - `code`: success — `redirect_uri?code=...&state=...`
 * - `consent`: user consent required — the configured consent page, with a
 *   `consent_code` to post back to the consent endpoint
 * - `error`: a spec-level error redirected to the client per RFC 6749 —
 *   `redirect_uri?error=...&state=...`
 */
export type OIDCAuthorizeResult =
  | { readonly type: "code"; readonly redirectTo: string }
  | { readonly type: "consent"; readonly redirectTo: string; readonly consentCode: string }
  | { readonly type: "error"; readonly redirectTo: string; readonly error: string };

/** A parsed `POST /oauth2/token` request (snake_case per RFC 6749). */
export interface OIDCTokenRequest {
  readonly grantType: string;
  readonly code?: string;
  readonly redirectUri?: string;
  readonly codeVerifier?: string;
  readonly refreshToken?: string;
  /** Client credentials from the request body or the Basic Authorization header. */
  readonly clientId?: string;
  readonly clientSecret?: string;
  /** Optional down-scoped scope list for the refresh_token grant (RFC 6749 §6). */
  readonly scope?: string;
}

/** A successful token response (camelCase; the HTTP layer encodes snake_case). */
export interface OIDCTokenResult {
  readonly accessToken: string;
  readonly tokenType: "Bearer";
  /** Seconds until the access token expires. */
  readonly expiresIn: number;
  readonly refreshToken?: string;
  readonly idToken?: string;
  readonly scope: string;
}

/** A statically configured, implicitly trusted client (consent skipped). */
export interface TrustedOIDCClient {
  readonly clientId: string;
  /** Plaintext secret (hashed at service creation); omit for public clients. */
  readonly clientSecret?: Redacted.Redacted<string>;
  readonly name: string;
  readonly redirectUris: readonly string[];
  readonly type?: "web" | "native";
  readonly skipConsent?: boolean;
}

/** Configuration for {@link make}. */
export interface OIDCProviderConfig {
  /**
   * Issuer identifier: the external base URL where the auth handler is
   * mounted (e.g. `https://app.example.com/api/auth`). Used as the `iss`
   * claim and to derive the discovery document endpoints.
   */
  readonly issuer: string;
  /** Where to redirect unauthenticated authorization requests. */
  readonly loginPage: string;
  /**
   * Consent page URL. Authorization requests that need consent redirect here
   * with `consent_code`, `client_id`, and `scope` query parameters; the page
   * posts the user's decision to the consent endpoint. When unset, requests
   * requiring consent are answered with an `error=consent_required` redirect.
   */
  readonly consentPage?: string;
  /** Authorization code lifetime in ms (default: 10 minutes). */
  readonly codeExpiresIn?: number;
  /** Access token lifetime in ms (default: 1 hour). */
  readonly accessTokenExpiresIn?: number;
  /** Refresh token lifetime in ms (default: 30 days). */
  readonly refreshTokenExpiresIn?: number;
  /** Scopes clients may request (default: `openid profile email offline_access`). */
  readonly allowedScopes?: readonly string[];
  /** Require PKCE from confidential clients too (default: `false`). */
  readonly requirePKCE?: boolean;
  /** Statically configured first-party clients (consent skipped by default). */
  readonly trustedClients?: readonly TrustedOIDCClient[];
}

export class OIDCProviderService extends Context.Service<
  OIDCProviderService,
  {
    /**
     * Register a client application. Generates the `client_id` and — for `web`
     * (confidential) clients — a secret returned in plaintext exactly once.
     * Gate this behind an admin check at the HTTP layer.
     */
    readonly registerClient: (
      input: RegisterOIDCClientInput,
      registrarUserId?: string,
    ) => Effect.Effect<RegisteredOIDCClient, OIDCProviderError | AuthError>;

    /** Look up a client (trusted config clients first, then the store). */
    readonly getClient: (clientId: string) => Effect.Effect<OIDCClient | null, AuthError>;

    /** List registered clients (store-backed only). */
    readonly listClients: () => Effect.Effect<ReadonlyArray<OIDCClient>, AuthError>;

    /** Update a registered client. Trusted config clients cannot be updated. */
    readonly updateClient: (
      clientId: string,
      input: UpdateOIDCClientInput,
    ) => Effect.Effect<OIDCClient, OIDCProviderError | AuthError>;

    /** Delete a registered client. */
    readonly deleteClient: (clientId: string) => Effect.Effect<void, OIDCProviderError | AuthError>;

    /**
     * Process an authorization request for an authenticated user. Fails with
     * {@link OIDCProviderError} only for errors that must NOT redirect back to
     * the client (unknown client, unregistered `redirect_uri`); every other
     * outcome is a redirect (code, consent page, or spec error).
     */
    readonly authorize: (
      user: Types.User,
      request: OIDCAuthorizeRequest,
    ) => Effect.Effect<OIDCAuthorizeResult, OIDCProviderError | AuthError>;

    /**
     * Resolve a pending consent request. Accepting records the consent and
     * issues an authorization code; denying redirects with
     * `error=access_denied`. The `userId` must match the pending request.
     */
    readonly consent: (
      userId: string,
      consentCode: string,
      accept: boolean,
    ) => Effect.Effect<{ readonly redirectTo: string }, OIDCProviderError | AuthError>;

    /**
     * Token endpoint: `authorization_code` (with PKCE verification) and
     * `refresh_token` (rotating) grants. Client authentication accepts a
     * secret for confidential clients; public clients must present a PKCE
     * verifier instead.
     */
    readonly token: (
      request: OIDCTokenRequest,
    ) => Effect.Effect<OIDCTokenResult, OIDCTokenError | AuthError>;

    /**
     * Resolve the standard claims for a bearer access token
     * (`sub` always; `email`/`email_verified` with the `email` scope;
     * `name`/`picture` with the `profile` scope).
     */
    readonly userinfo: (
      accessToken: string,
    ) => Effect.Effect<Record<string, unknown>, OIDCProviderError | AuthError>;

    /** The OpenID Provider Metadata document (RFC 8414 / OIDC Discovery). */
    readonly getMetadata: () => Record<string, unknown>;

    /**
     * The login page URL for an unauthenticated authorization request, with the
     * original authorize URL attached as `redirect_to` so the app can resume
     * the flow after sign-in.
     */
    readonly loginRedirect: (returnTo: string) => string;
  }
>()("@effect-auth/OIDCProviderService") {
  /**
   * Construct a Layer providing this service.
   */
  static readonly layer = (config: OIDCProviderConfig) =>
    Layer.effect(OIDCProviderService, make(config)).pipe(Layer.provide(PlatformCrypto.layer));
}

// -----------------------------------------------------------------------------
// Helpers
// -----------------------------------------------------------------------------

/** SHA-256 hex digest used for every OIDC secret at rest (tokens, codes, secrets). */
export const hashOIDCSecret = hashToken;

/** Constant-time equality of two strings via their SHA-256 digests. */
const secretEquals = (a: string, b: string): boolean =>
  constantTimeHashEqual(hashToken(a), hashToken(b));

/** Append query parameters to a URL that may already carry a query string. */
const buildRedirect = (base: string, params: Record<string, string | undefined>): string => {
  const url = new URL(base);
  for (const [key, value] of Object.entries(params)) {
    if (value !== undefined) url.searchParams.set(key, value);
  }
  return url.toString();
};

const parseScopes = (scope: string | undefined): readonly string[] =>
  (scope ?? "").split(" ").filter((s) => s.length > 0);

export const DEFAULT_OIDC_SCOPES = ["openid", "profile", "email", "offline_access"] as const;

/**
 * Validates that a redirect URI is either https or loopback http.
 * Blocks javascript:, data:, and non-loopback http URIs (RFC 8252 §7.3).
 */
const isAllowedRedirectUri = (uri: string): boolean => {
  let parsed: URL;
  try {
    parsed = new URL(uri);
  } catch {
    return false;
  }
  if (parsed.protocol === "https:") return true;
  if (parsed.protocol === "http:") {
    const h = parsed.hostname;
    return h === "127.0.0.1" || h === "[::1]" || h === "localhost";
  }
  return false;
};

// -----------------------------------------------------------------------------
// Service implementation
// -----------------------------------------------------------------------------

export const make = (
  config: OIDCProviderConfig,
): Effect.Effect<
  typeof OIDCProviderService.Service,
  never,
  | OIDCClientStore
  | OIDCCodeStore
  | OIDCConsentStore
  | OIDCTokenStore
  | UserStore
  | JWTService
  | Crypto.Crypto
> =>
  Effect.gen(function* () {
    const codeExpiresIn = config.codeExpiresIn ?? 10 * 60 * 1000;
    const accessTokenExpiresIn = config.accessTokenExpiresIn ?? 60 * 60 * 1000;
    const refreshTokenExpiresIn = config.refreshTokenExpiresIn ?? 30 * 24 * 60 * 60 * 1000;
    const allowedScopes = config.allowedScopes ?? DEFAULT_OIDC_SCOPES;

    /**
     * In-process registry of consumed refresh-token hashes → their family.
     * Lets us detect a reuse attack (RFC 6819 §6.1): if a hash appears here it
     * was already rotated; presenting it again means a stolen token is in play.
     * Entries are pruned once their absolute expiry passes.
     */
    const consumedRefreshTokens = new Map<
      string,
      { familyId: string; absoluteExpiresAt: number }
    >();
    const pruneConsumed = () => {
      const now = Date.now();
      for (const [hash, entry] of consumedRefreshTokens) {
        if (now > entry.absoluteExpiresAt) consumedRefreshTokens.delete(hash);
      }
    };

    /** Trusted config clients, normalized to the stored shape (secret hashed). */
    const trustedClients = new Map<string, OIDCClient>(
      (config.trustedClients ?? []).map((c) => [
        c.clientId,
        {
          clientId: c.clientId,
          ...(c.clientSecret !== undefined && {
            clientSecretHash: hashOIDCSecret(Redacted.value(c.clientSecret)),
          }),
          name: c.name,
          redirectUris: c.redirectUris,
          type: c.type ?? "web",
          skipConsent: c.skipConsent ?? true,
          disabled: false,
          metadata: {},
          createdAt: 0,
          updatedAt: 0,
        } satisfies OIDCClient,
      ]),
    );

    const clientStore = yield* OIDCClientStore;
    const codeStore = yield* OIDCCodeStore;
    const consentStore = yield* OIDCConsentStore;
    const tokenStore = yield* OIDCTokenStore;
    const userStore = yield* UserStore;
    const jwt = yield* JWTService;
    const crypto = yield* Crypto.Crypto;

    const randomToken = (): Effect.Effect<string, AuthError> =>
      crypto.randomBytes(32).pipe(
        Effect.map((bytes) => Buffer.from(bytes).toString("base64url")),
        Effect.mapError((cause) => new AuthError({ message: "Failed to generate token", cause })),
      );

    const randomClientId = (): Effect.Effect<string, AuthError> =>
      crypto.randomBytes(16).pipe(
        Effect.map((bytes) => Buffer.from(bytes).toString("hex")),
        Effect.mapError(
          (cause) => new AuthError({ message: "Failed to generate client id", cause }),
        ),
      );

    /** SHA-256 digest of the PKCE code verifier, base64url-encoded. */
    const hashCodeVerifier = (verifier: string): Effect.Effect<string, AuthError> =>
      crypto.digest("SHA-256", new TextEncoder().encode(verifier)).pipe(
        Effect.map((bytes) => Buffer.from(bytes).toString("base64url")),
        Effect.mapError(
          (cause) => new AuthError({ message: "Failed to hash code verifier", cause }),
        ),
      );

    const getClient = (clientId: string) =>
      Effect.gen(function* () {
        const trusted = trustedClients.get(clientId);
        if (trusted !== undefined) return trusted;
        return yield* clientStore.getByClientId(clientId);
      });

    /** Create + persist an authorization-code (or pending-consent) record. */
    const issueCode = (
      kind: OIDCAuthorizationCode["kind"],
      base: Omit<OIDCAuthorizationCode, "codeHash" | "kind" | "expiresAt" | "createdAt">,
    ) =>
      Effect.gen(function* () {
        const value = yield* randomToken();
        const now = Date.now();
        yield* codeStore.create({
          ...base,
          codeHash: hashOIDCSecret(value),
          kind,
          expiresAt: now + codeExpiresIn,
          createdAt: now,
        });
        return value;
      });

    /** Build the standard claims for a user, filtered by granted scopes. */
    const claimsFor = (user: Types.User, scopes: readonly string[]): Record<string, unknown> => ({
      sub: user.id,
      ...(scopes.includes("profile") && {
        ...(user.name !== undefined && { name: user.name }),
        ...(user.image !== undefined && { picture: user.image }),
        updated_at: Math.floor(user.updatedAt.getTime() / 1000),
      }),
      ...(scopes.includes("email") && {
        email: user.email,
        email_verified: user.emailVerified,
      }),
    });

    /** Mint access (+ refresh) tokens and the id_token for a grant. */
    const issueTokens = (grant: {
      readonly clientId: string;
      readonly userId: string;
      readonly scopes: readonly string[];
      readonly nonce?: string;
      /** Rotation family ID carried through from the original grant. */
      readonly familyId?: string;
      /** Absolute (non-sliding) expiry for the whole refresh family. */
      readonly absoluteExpiresAt?: number;
    }) =>
      Effect.gen(function* () {
        const now = Date.now();

        // Mint the id_token FIRST — a signing failure here must not leave
        // orphaned access/refresh tokens that can never be revoked.
        let idToken: string | undefined;
        if (grant.scopes.includes("openid")) {
          const user = yield* userStore
            .get(grant.userId)
            .pipe(
              Effect.mapError(
                (e) => new OIDCTokenError({ error: "invalid_grant", description: e.message }),
              ),
            );
          if (user === null) {
            return yield* new OIDCTokenError({
              error: "invalid_grant",
              description: "Unknown user",
            });
          }
          const signed = yield* jwt
            .sign(user, {
              iss: config.issuer,
              aud: grant.clientId,
              ...(grant.nonce !== undefined && { nonce: grant.nonce }),
              ...claimsFor(user, grant.scopes),
            })
            .pipe(
              Effect.catchTag("JWTError", (e) =>
                Effect.fail(new OIDCTokenError({ error: "server_error", description: e.message })),
              ),
            );
          idToken = signed.token;
        }

        const accessToken = yield* randomToken();
        yield* tokenStore.create({
          tokenHash: hashOIDCSecret(accessToken),
          kind: "access",
          clientId: grant.clientId,
          userId: grant.userId,
          scopes: grant.scopes,
          expiresAt: now + accessTokenExpiresIn,
          createdAt: now,
        });

        let refreshToken: string | undefined;
        if (grant.scopes.includes("offline_access")) {
          refreshToken = yield* randomToken();
          const familyId = grant.familyId ?? (yield* randomToken());
          const absoluteExpiresAt = grant.absoluteExpiresAt ?? now + refreshTokenExpiresIn;
          yield* tokenStore.create({
            tokenHash: hashOIDCSecret(refreshToken),
            kind: "refresh",
            clientId: grant.clientId,
            userId: grant.userId,
            scopes: grant.scopes,
            // Sliding window capped at the absolute lifetime.
            expiresAt: Math.min(now + refreshTokenExpiresIn, absoluteExpiresAt),
            createdAt: now,
            familyId,
            absoluteExpiresAt,
          });
        }

        return {
          accessToken,
          tokenType: "Bearer",
          expiresIn: Math.floor(accessTokenExpiresIn / 1000),
          ...(refreshToken !== undefined && { refreshToken }),
          ...(idToken !== undefined && { idToken }),
          scope: grant.scopes.join(" "),
        } satisfies OIDCTokenResult;
      });

    /**
     * Authenticate the client for a token request: confidential clients must
     * present their secret; public clients authenticate via PKCE (checked by
     * the grant handling).
     */
    const authenticateClient = (request: OIDCTokenRequest) =>
      Effect.gen(function* () {
        if (request.clientId === undefined) {
          return yield* new OIDCTokenError({
            error: "invalid_client",
            description: "Missing client_id",
          });
        }
        const client = yield* getClient(request.clientId);
        if (client === null || client.disabled) {
          return yield* new OIDCTokenError({
            error: "invalid_client",
            description: "Unknown client",
          });
        }
        if (client.clientSecretHash !== undefined) {
          if (
            request.clientSecret === undefined ||
            !secretEquals(hashOIDCSecret(request.clientSecret), client.clientSecretHash)
          ) {
            return yield* new OIDCTokenError({
              error: "invalid_client",
              description: "Invalid client credentials",
            });
          }
        }
        return client;
      });

    return {
      registerClient: Effect.fn("OIDCProviderService.registerClient")(function* (
        input: RegisterOIDCClientInput,
        registrarUserId?: string,
      ) {
        if (input.redirectUris.length === 0) {
          return yield* new OIDCProviderError({
            message: "At least one redirect URI is required",
          });
        }
        for (const uri of input.redirectUris) {
          if (!isAllowedRedirectUri(uri)) {
            return yield* new OIDCProviderError({
              message: `Redirect URI must be https or loopback http: ${uri}`,
            });
          }
        }
        const type = input.type ?? "web";
        const clientSecret = type === "web" ? yield* randomToken() : undefined;
        const clientId = yield* randomClientId();
        const now = Date.now();
        const client = yield* clientStore.create({
          clientId,
          ...(clientSecret !== undefined && { clientSecretHash: hashOIDCSecret(clientSecret) }),
          name: input.name,
          redirectUris: input.redirectUris,
          type,
          skipConsent: input.skipConsent ?? false,
          disabled: false,
          metadata: input.metadata ?? {},
          ...(registrarUserId !== undefined && { userId: registrarUserId }),
          createdAt: now,
          updatedAt: now,
        });
        return {
          client,
          ...(clientSecret !== undefined && { clientSecret }),
        } satisfies RegisteredOIDCClient;
      }),

      getClient: Effect.fn("OIDCProviderService.getClient")(getClient),

      listClients: Effect.fn("OIDCProviderService.listClients")(function* () {
        return yield* clientStore.list();
      }),

      updateClient: Effect.fn("OIDCProviderService.updateClient")(function* (
        clientId: string,
        input: UpdateOIDCClientInput,
      ) {
        if (trustedClients.has(clientId)) {
          return yield* new OIDCProviderError({
            message: "Trusted clients are configured statically and cannot be updated",
          });
        }
        const existing = yield* clientStore.getByClientId(clientId);
        if (existing === null) {
          return yield* new OIDCProviderError({ message: "Client not found" });
        }
        return yield* clientStore.update({
          ...existing,
          ...(input.name !== undefined && { name: input.name }),
          ...(input.redirectUris !== undefined && { redirectUris: input.redirectUris }),
          ...(input.skipConsent !== undefined && { skipConsent: input.skipConsent }),
          ...(input.disabled !== undefined && { disabled: input.disabled }),
          ...(input.metadata !== undefined && { metadata: input.metadata }),
          updatedAt: Date.now(),
        });
      }),

      deleteClient: Effect.fn("OIDCProviderService.deleteClient")(function* (clientId: string) {
        const existing = yield* clientStore.getByClientId(clientId);
        if (existing === null) {
          return yield* new OIDCProviderError({ message: "Client not found" });
        }
        yield* clientStore.delete(clientId);
      }),

      authorize: Effect.fn("OIDCProviderService.authorize")(
        (user: Types.User, request: OIDCAuthorizeRequest) =>
          Effect.gen(function* () {
            // Unknown client / unregistered redirect_uri: NEVER redirect (RFC 6749 §4.1.2.1).
            const client = yield* getClient(request.clientId);
            if (client === null || client.disabled) {
              return yield* new OIDCProviderError({ message: "Unknown client" });
            }
            if (!client.redirectUris.includes(request.redirectUri)) {
              return yield* new OIDCProviderError({ message: "Unregistered redirect_uri" });
            }

            const errorRedirect = (error: string): OIDCAuthorizeResult => ({
              type: "error",
              error,
              redirectTo: buildRedirect(request.redirectUri, {
                error,
                ...(request.state !== undefined && { state: request.state }),
              }),
            });

            if (request.responseType !== "code") {
              return errorRedirect("unsupported_response_type");
            }

            const scopes = parseScopes(request.scope);
            if (!scopes.includes("openid") || scopes.some((s) => !allowedScopes.includes(s))) {
              return errorRedirect("invalid_scope");
            }

            // PKCE: mandatory for public clients (and everyone under `requirePKCE`).
            const pkceRequired = client.type === "native" || (config.requirePKCE ?? false);
            if (request.codeChallenge === undefined) {
              if (pkceRequired) return errorRedirect("invalid_request");
            } else if ((request.codeChallengeMethod ?? "S256") !== "S256") {
              // Only S256 is supported; `plain` defeats the point of PKCE.
              return errorRedirect("invalid_request");
            }

            const codeFields = {
              clientId: client.clientId,
              userId: user.id,
              scopes,
              redirectUri: request.redirectUri,
              ...(request.state !== undefined && { state: request.state }),
              ...(request.codeChallenge !== undefined && {
                codeChallenge: request.codeChallenge,
                codeChallengeMethod: "S256" as const,
              }),
              ...(request.nonce !== undefined && { nonce: request.nonce }),
            };

            // Consent: skipped for trusted/first-party clients, or when a prior
            // consent already covers every requested scope (unless prompt=consent).
            let consentNeeded = !client.skipConsent;
            if (consentNeeded && request.prompt !== "consent") {
              const existing = yield* consentStore.get(user.id, client.clientId);
              if (existing !== null && scopes.every((s) => existing.scopes.includes(s))) {
                consentNeeded = false;
              }
            }

            // prompt=none: no UI may be shown — return immediately with an error
            // if interaction is needed (RFC 6749 / OIDC Core §3.1.2.1).
            if (request.prompt === "none" && consentNeeded) {
              return errorRedirect("interaction_required");
            }

            if (consentNeeded) {
              if (config.consentPage === undefined) {
                return errorRedirect("consent_required");
              }
              const consentCode = yield* issueCode("pending_consent", codeFields);
              return {
                type: "consent",
                consentCode,
                redirectTo: buildRedirect(config.consentPage, {
                  consent_code: consentCode,
                  client_id: client.clientId,
                  client_name: client.name,
                  scope: scopes.join(" "),
                  ...(request.state !== undefined && { state: request.state }),
                }),
              } satisfies OIDCAuthorizeResult;
            }

            const code = yield* issueCode("authorization_code", codeFields);
            return {
              type: "code",
              redirectTo: buildRedirect(request.redirectUri, {
                code,
                ...(request.state !== undefined && { state: request.state }),
              }),
            } satisfies OIDCAuthorizeResult;
          }).pipe(Effect.withSpan("effect-auth.oidc.authorize")),
      ),

      consent: Effect.fn("OIDCProviderService.consent")(
        (userId: string, consentCode: string, accept: boolean) =>
          Effect.gen(function* () {
            const pending = yield* codeStore.get(hashOIDCSecret(consentCode));
            if (
              pending === null ||
              pending.kind !== "pending_consent" ||
              pending.userId !== userId ||
              Date.now() > pending.expiresAt
            ) {
              return yield* new OIDCProviderError({
                message: "Consent request not found or expired",
              });
            }
            yield* codeStore.delete(pending.codeHash);

            if (!accept) {
              return {
                redirectTo: buildRedirect(pending.redirectUri, {
                  error: "access_denied",
                  ...(pending.state !== undefined && { state: pending.state }),
                }),
              };
            }

            const now = Date.now();
            const existing = yield* consentStore.get(userId, pending.clientId);
            yield* consentStore.upsert({
              userId,
              clientId: pending.clientId,
              // Accumulate scopes across grants so consent is asked once per scope.
              scopes: [...new Set([...(existing?.scopes ?? []), ...pending.scopes])],
              createdAt: existing?.createdAt ?? now,
              updatedAt: now,
            });

            const {
              codeHash: _hash,
              kind: _kind,
              expiresAt: _e,
              createdAt: _c,
              ...fields
            } = pending;
            const code = yield* issueCode("authorization_code", fields);
            return {
              redirectTo: buildRedirect(pending.redirectUri, {
                code,
                ...(pending.state !== undefined && { state: pending.state }),
              }),
            };
          }).pipe(Effect.withSpan("effect-auth.oidc.consent")),
      ),

      token: Effect.fn("OIDCProviderService.token")((request: OIDCTokenRequest) =>
        Effect.gen(function* () {
          const client = yield* authenticateClient(request);

          if (request.grantType === "authorization_code") {
            if (request.code === undefined) {
              return yield* new OIDCTokenError({
                error: "invalid_request",
                description: "Missing code",
              });
            }
            const record = yield* codeStore.get(hashOIDCSecret(request.code));
            if (
              record === null ||
              record.kind !== "authorization_code" ||
              record.clientId !== client.clientId
            ) {
              return yield* new OIDCTokenError({ error: "invalid_grant" });
            }
            // Single use: burn the code before any further checks so a replay
            // (even with corrected parameters) always fails.
            yield* codeStore.delete(record.codeHash);
            if (Date.now() > record.expiresAt) {
              return yield* new OIDCTokenError({
                error: "invalid_grant",
                description: "Code expired",
              });
            }
            if (request.redirectUri !== record.redirectUri) {
              return yield* new OIDCTokenError({
                error: "invalid_grant",
                description: "redirect_uri mismatch",
              });
            }
            if (record.codeChallenge !== undefined) {
              const computedChallenge =
                request.codeVerifier !== undefined
                  ? yield* hashCodeVerifier(request.codeVerifier)
                  : undefined;
              if (
                computedChallenge === undefined ||
                !secretEquals(computedChallenge, record.codeChallenge)
              ) {
                return yield* new OIDCTokenError({
                  error: "invalid_grant",
                  description: "PKCE verification failed",
                });
              }
            } else if (client.clientSecretHash === undefined) {
              // Public client without PKCE: never issue tokens.
              return yield* new OIDCTokenError({
                error: "invalid_grant",
                description: "PKCE required",
              });
            }
            return yield* issueTokens({
              clientId: client.clientId,
              userId: record.userId,
              scopes: record.scopes,
              ...(record.nonce !== undefined && { nonce: record.nonce }),
            });
          }

          if (request.grantType === "refresh_token") {
            if (request.refreshToken === undefined) {
              return yield* new OIDCTokenError({
                error: "invalid_request",
                description: "Missing refresh_token",
              });
            }

            pruneConsumed();
            const presentedHash = hashOIDCSecret(request.refreshToken);
            const record = yield* tokenStore.get(presentedHash);

            if (
              record === null ||
              record.kind !== "refresh" ||
              record.clientId !== client.clientId
            ) {
              // Check if this hash was already consumed — if so, it's a reuse attack.
              const consumed = consumedRefreshTokens.get(presentedHash);
              if (consumed !== undefined) {
                // Revoke the entire family to protect the user (RFC 6819 §6.1).
                yield* Effect.gen(function* () {
                  const listByFamily = tokenStore.listByFamily;
                  if (listByFamily === undefined) return;
                  const family = yield* listByFamily(consumed.familyId);
                  yield* Effect.forEach(family, (t) => tokenStore.delete(t.tokenHash), {
                    concurrency: "unbounded",
                  });
                });
              }
              return yield* new OIDCTokenError({ error: "invalid_grant" });
            }

            // Rotation: burn the presented token immediately.
            yield* tokenStore.delete(record.tokenHash);

            // Carry the family lineage and absolute lifetime through all rotations.
            const familyId = record.familyId ?? (yield* randomToken());
            const absoluteExpiresAt = record.absoluteExpiresAt ?? record.expiresAt;

            // Record as consumed for reuse detection.
            consumedRefreshTokens.set(presentedHash, { familyId, absoluteExpiresAt });

            // Absolute (non-sliding) lifetime check.
            if (Date.now() > absoluteExpiresAt) {
              return yield* new OIDCTokenError({
                error: "invalid_grant",
                description: "Refresh token expired",
              });
            }

            // RFC 6749 §6: client may request a strict subset of original scopes.
            let effectiveScopes = record.scopes;
            if (request.scope !== undefined) {
              const requested = parseScopes(request.scope);
              if (requested.some((s) => !record.scopes.includes(s))) {
                return yield* new OIDCTokenError({
                  error: "invalid_scope",
                  description: "Requested scopes exceed those of the original grant",
                });
              }
              effectiveScopes = requested;
            }

            return yield* issueTokens({
              clientId: client.clientId,
              userId: record.userId,
              scopes: effectiveScopes,
              familyId,
              absoluteExpiresAt,
            });
          }

          return yield* new OIDCTokenError({ error: "unsupported_grant_type" });
        }).pipe(
          Effect.withSpan("effect-auth.oidc.token", { attributes: { grant: request.grantType } }),
          Effect.tap(() => Obs.recordOIDCTokenRequest(request.grantType, "success")),
          Effect.tapError(() => Obs.recordOIDCTokenRequest(request.grantType, "failure")),
        ),
      ),

      userinfo: Effect.fn("OIDCProviderService.userinfo")((accessToken: string) =>
        Effect.gen(function* () {
          const record = yield* tokenStore.get(hashOIDCSecret(accessToken));
          if (record === null || record.kind !== "access" || Date.now() > record.expiresAt) {
            return yield* new OIDCProviderError({ message: "Invalid or expired access token" });
          }
          const user = yield* userStore
            .get(record.userId)
            .pipe(
              Effect.mapError(
                () => new OIDCProviderError({ message: "Invalid or expired access token" }),
              ),
            );
          if (user === null) {
            return yield* new OIDCProviderError({ message: "Invalid or expired access token" });
          }
          return claimsFor(user, record.scopes);
        }).pipe(Effect.withSpan("effect-auth.oidc.userinfo")),
      ),

      getMetadata: () => ({
        issuer: config.issuer,
        authorization_endpoint: `${config.issuer}/oauth2/authorize`,
        token_endpoint: `${config.issuer}/oauth2/token`,
        userinfo_endpoint: `${config.issuer}/oauth2/userinfo`,
        jwks_uri: `${config.issuer}/.well-known/jwks.json`,
        registration_endpoint: `${config.issuer}/oauth2/register`,
        end_session_endpoint: `${config.issuer}/oauth2/logout`,
        scopes_supported: [...allowedScopes],
        response_types_supported: ["code"],
        response_modes_supported: ["query"],
        grant_types_supported: ["authorization_code", "refresh_token"],
        subject_types_supported: ["public"],
        id_token_signing_alg_values_supported: ["ES256", "EdDSA"],
        token_endpoint_auth_methods_supported: [
          "client_secret_basic",
          "client_secret_post",
          "none",
        ],
        code_challenge_methods_supported: ["S256"],
        claims_supported: ["sub", "email", "email_verified", "name", "picture", "updated_at"],
      }),

      loginRedirect: (returnTo: string) =>
        buildRedirect(config.loginPage, { redirect_to: returnTo }),
    };
  });
