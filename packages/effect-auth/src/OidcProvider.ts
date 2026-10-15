/**
 * OIDC Provider — act as an OpenID Connect identity provider.
 *
 * Mirrors better-auth's `oidc-provider` plugin: register client applications,
 * run the authorization-code flow (with PKCE), handle consent, and issue
 * opaque access/refresh tokens plus signed `id_token`s so third-party apps can
 * federate sign-in to this server.
 *
 * The `id_token` is signed with the {@link module:jwt} `JwtService`, sharing
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
import { AuthError, ClientAddressConfigError } from "./Errors.ts";
import { JwtService } from "./Jwt.ts";
import * as Obs from "./Observability.ts";
import * as PlatformCrypto from "./PlatformCrypto.ts";
import type { TrustedProxyConfig } from "./ClientIP.ts";
import type { RateLimitConfig } from "./RateLimit.ts";
import { UserStore } from "./UserStore.ts";
import { anyEmail, IdentifierStore } from "./Identifier.ts";
import { constantTimeHashEqual, hashToken } from "./TokenHash.ts";
import type * as Types from "./Types.ts";

/** Failure to register a client or process an authorization request. */
export class OidcProviderError extends Data.TaggedError("OidcProviderError")<{
  readonly message: string;
  readonly cause?: unknown;
}> {}

/**
 * Token endpoint failure carrying an RFC 6749 error code
 * (`invalid_request`, `invalid_client`, `invalid_grant`,
 * `unsupported_grant_type`, `invalid_scope`, `server_error`).
 */
export class OidcTokenError extends Data.TaggedError("OidcTokenError")<{
  readonly error: string;
  readonly description?: string;
}> {}

/**
 * Dynamic client registration failure carrying an RFC 7591 §3.2.2 error code
 * (`invalid_redirect_uri`, `invalid_client_metadata`), plus the two codes the
 * guarded endpoints need: `invalid_token` (bad initial-access or registration
 * access token → 401) and `access_denied` (refused outright → 403).
 */
export class OidcRegistrationError extends Data.TaggedError("OidcRegistrationError")<{
  readonly error: string;
  readonly description?: string;
}> {}

// -----------------------------------------------------------------------------
// Records + stores
// -----------------------------------------------------------------------------

/** A registered OAuth2/OIDC client application. */
export interface OidcClient {
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
  /**
   * sha256 hex digest of the RFC 7592 registration access token. Present only
   * for clients created through dynamic registration; it authenticates the
   * `GET`/`PUT`/`DELETE {issuer}/register/:clientId` management calls.
   */
  readonly registrationAccessTokenHash?: string;
  /** RFC 7591 `token_endpoint_auth_method`. `none` marks a public client. */
  readonly tokenEndpointAuthMethod?: OidcTokenEndpointAuthMethod;
  /**
   * RFC 7591 `grant_types` the client registered for. When present the token
   * endpoint refuses any other grant with `unauthorized_client`; when absent
   * (statically/admin-registered clients) every supported grant is allowed.
   */
  readonly grantTypes?: readonly string[];
  /** RFC 7591 `response_types` the client registered for. */
  readonly responseTypes?: readonly string[];
  /**
   * Space-separated scopes the client registered for. When present the
   * authorization endpoint rejects requests for anything outside this set.
   */
  readonly scope?: string;
  /** `true` when the client was created via RFC 7591 dynamic registration. */
  readonly dynamicallyRegistered?: boolean;
}

/** Persistent registry of OIDC clients. */
export class OidcClientStore extends Context.Service<
  OidcClientStore,
  {
    readonly create: (client: OidcClient) => Effect.Effect<OidcClient, AuthError>;
    readonly getByClientId: (clientId: string) => Effect.Effect<OidcClient | null, AuthError>;
    readonly update: (client: OidcClient) => Effect.Effect<OidcClient, AuthError>;
    readonly delete: (clientId: string) => Effect.Effect<void, AuthError>;
    readonly list: () => Effect.Effect<ReadonlyArray<OidcClient>, AuthError>;
  }
>()("@effect-auth/OidcClientStore") {}

/**
 * A short-lived authorization artifact: either an issued authorization code
 * (`kind: "authorization_code"`) or a pending consent request
 * (`kind: "pending_consent"`), keyed by the sha256 hex digest of the
 * user-visible value.
 */
export interface OidcAuthorizationCode {
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
export class OidcCodeStore extends Context.Service<
  OidcCodeStore,
  {
    readonly create: (
      code: OidcAuthorizationCode,
    ) => Effect.Effect<OidcAuthorizationCode, AuthError>;
    readonly get: (codeHash: string) => Effect.Effect<OidcAuthorizationCode | null, AuthError>;
    readonly delete: (codeHash: string) => Effect.Effect<void, AuthError>;
  }
>()("@effect-auth/OidcCodeStore") {}

/** An issued opaque token, keyed by the sha256 hex digest of its value. */
export interface OidcToken {
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
export class OidcTokenStore extends Context.Service<
  OidcTokenStore,
  {
    readonly create: (token: OidcToken) => Effect.Effect<OidcToken, AuthError>;
    readonly get: (tokenHash: string) => Effect.Effect<OidcToken | null, AuthError>;
    readonly delete: (tokenHash: string) => Effect.Effect<void, AuthError>;
    /** Optional: list all tokens belonging to a rotation family. Used for reuse-detection revocation. */
    readonly listByFamily?: (
      familyId: string,
    ) => Effect.Effect<ReadonlyArray<OidcToken>, AuthError>;
  }
>()("@effect-auth/OidcTokenStore") {}

/** A user's recorded consent for a client (the union of granted scopes). */
export interface OidcConsent {
  readonly userId: string;
  readonly clientId: string;
  readonly scopes: readonly string[];
  /** Epoch milliseconds. */
  readonly createdAt: number;
  readonly updatedAt: number;
}

/** Store for recorded user consents. */
export class OidcConsentStore extends Context.Service<
  OidcConsentStore,
  {
    readonly get: (
      userId: string,
      clientId: string,
    ) => Effect.Effect<OidcConsent | null, AuthError>;
    readonly upsert: (consent: OidcConsent) => Effect.Effect<OidcConsent, AuthError>;
    readonly delete: (userId: string, clientId: string) => Effect.Effect<void, AuthError>;
  }
>()("@effect-auth/OidcConsentStore") {}

// -----------------------------------------------------------------------------
// Service types
// -----------------------------------------------------------------------------

/** Input to {@link OidcProviderService.registerClient}. */
export interface RegisterOidcClientInput {
  readonly name: string;
  readonly redirectUris: readonly string[];
  /** Default `"web"` (confidential — a secret is generated). */
  readonly type?: "web" | "native";
  /** Default `false`. */
  readonly skipConsent?: boolean;
  readonly metadata?: Record<string, unknown>;
}

/** Result of registering a client: the plaintext secret is shown exactly once. */
export interface RegisteredOidcClient {
  readonly client: OidcClient;
  /** Only present for `web` (confidential) clients. */
  readonly clientSecret?: string;
}

/** Fields updatable via {@link OidcProviderService.updateClient}. */
export interface UpdateOidcClientInput {
  readonly name?: string;
  readonly redirectUris?: readonly string[];
  readonly skipConsent?: boolean;
  readonly disabled?: boolean;
  readonly metadata?: Record<string, unknown>;
}

// -----------------------------------------------------------------------------
// RFC 7591 dynamic client registration
// -----------------------------------------------------------------------------

/** Client authentication methods the token endpoint implements. */
export const OIDC_TOKEN_ENDPOINT_AUTH_METHODS = [
  "client_secret_basic",
  "client_secret_post",
  "none",
] as const;
/** How a client authenticates at the token endpoint: one of `OIDC_TOKEN_ENDPOINT_AUTH_METHODS`. */
export type OidcTokenEndpointAuthMethod = (typeof OIDC_TOKEN_ENDPOINT_AUTH_METHODS)[number];

/** Grant types a dynamically registered client may ask for. */
export const OIDC_DYNAMIC_GRANT_TYPES = ["authorization_code", "refresh_token"] as const;

/** Response types a dynamically registered client may ask for. */
export const OIDC_DYNAMIC_RESPONSE_TYPES = ["code"] as const;

/**
 * RFC 7591 §2 client metadata, camelCase (the HTTP layer decodes the
 * snake_case wire form). Members the provider does not implement
 * (`jwks`, `software_statement`, ...) are ignored rather than rejected.
 */
export interface OidcClientMetadata {
  /** Required. Exact-match redirect URIs; https or loopback http by default. */
  readonly redirectUris: readonly string[];
  /** Default `client_secret_basic` per RFC 7591 §2; `none` = public client. */
  readonly tokenEndpointAuthMethod?: string;
  /** Default `["authorization_code"]`. */
  readonly grantTypes?: readonly string[];
  /** Default `["code"]`. */
  readonly responseTypes?: readonly string[];
  readonly clientName?: string;
  /** Space-separated scope list. */
  readonly scope?: string;
}

/** {@link OidcClientMetadata} after validation, with every RFC default applied. */
export interface NormalizedOidcClientMetadata {
  readonly redirectUris: readonly string[];
  readonly tokenEndpointAuthMethod: OidcTokenEndpointAuthMethod;
  readonly grantTypes: readonly string[];
  readonly responseTypes: readonly string[];
  readonly clientName: string;
  readonly scope: string;
}

/**
 * A registration policy's verdict. `allow: false` is answered with
 * `invalid_client_metadata` (400) per RFC 7591 §3.2.2 unless `error` names a
 * different code — use `access_denied` for a 403-shaped refusal that is not
 * about the metadata itself.
 */
export interface OidcRegistrationDisposition {
  readonly allow: boolean;
  /** RFC 7591 §3.2.2 error code when denying. Default `invalid_client_metadata`. */
  readonly error?: string;
  readonly errorDescription?: string;
  /** Accepting: skip the consent screen for this client (default from config). */
  readonly skipConsent?: boolean;
}

/**
 * Gate for `POST {issuer}/register`, evaluated after the metadata is validated
 * and normalized. Return `true`/`false`, or an {@link OidcRegistrationDisposition}
 * to choose the error code or opt the client out of the consent screen.
 */
export type OidcRegistrationPolicy = (
  metadata: NormalizedOidcClientMetadata,
) => Effect.Effect<boolean | OidcRegistrationDisposition, AuthError>;

/**
 * Verifier for the optional initial access token (RFC 7591 §3.1) presented as
 * `Authorization: Bearer` on `POST {issuer}/register`.
 */
export type OidcInitialAccessTokenVerifier = (token: string) => Effect.Effect<boolean, AuthError>;

/** Rate limit applied to `POST {issuer}/register` per client IP. */
export const DEFAULT_OIDC_REGISTRATION_RATE_LIMIT: RateLimitConfig = {
  maxRequests: 10,
  windowMs: 60 * 60 * 1000,
  blockDurationMs: 60 * 60 * 1000,
};

/**
 * Enables RFC 7591 dynamic client registration. Registration is **off** until
 * this is set: `POST {issuer}/register` answers 404 without it.
 */
export interface OidcDynamicRegistrationConfig {
  /**
   * Deny/allow hook run against the normalized metadata. Without it every
   * well-formed registration is accepted (open registration) — pair it with
   * {@link initialAccessToken} for anything internet-facing.
   */
  readonly policy?: OidcRegistrationPolicy;
  /**
   * Require `Authorization: Bearer <initial access token>` on `POST /register`.
   * Either a shared secret (compared in constant time) or a verifier hook.
   */
  readonly initialAccessToken?: Redacted.Redacted<string> | OidcInitialAccessTokenVerifier;
  /**
   * Scope granted when the request omits `scope`. Defaults to the provider's
   * `allowedScopes`.
   */
  readonly defaultScope?: string;
  /** Skip the consent screen for dynamically registered clients (default `false`). */
  readonly skipConsent?: boolean;
  /**
   * Additional redirect-URI schemes accepted on top of https and loopback http
   * — e.g. `["myapp"]` to allow the RFC 8252 §7.1 private-use scheme
   * `myapp://callback`. Compared case-insensitively without the trailing `:`.
   */
  readonly allowedRedirectUriSchemes?: readonly string[];
  /**
   * Serve the RFC 7592 management endpoints
   * (`GET`/`PUT`/`DELETE {issuer}/register/:clientId`). Default `true`.
   */
  readonly management?: boolean;
  /**
   * Per-IP rate limit for `POST /register`, applied by the HTTP layer. Defaults
   * to {@link DEFAULT_OIDC_REGISTRATION_RATE_LIMIT}. The limit needs a
   * `RateLimiter` in the handler's `services`: without one, `Http.make` throws
   * `RateLimiterConfigError`, and the group layers composed outside `Http.make`
   * refuse every registration with `429`.
   */
  readonly rateLimit?: RateLimitConfig;
  /**
   * The client-address source the registration rate limit keys on. Declare the
   * source passed to `Http.make` as `trustedProxy` (for example
   * `ClientIP.cloudflare`), so {@link OidcProviderService.layer} can check at
   * build time that a limited registration has an address to key on. This layer
   * does not resolve addresses itself. Without `trustedProxy`, or the
   * {@link allowMissingClientIp} opt-out, the layer fails with
   * `ClientAddressConfigError`.
   */
  readonly trustedProxy?: TrustedProxyConfig | undefined;
  /**
   * Accept that registrations may have no client address, so `trustedProxy` can
   * be omitted. This opts out of the build-time check only. The limit still
   * runs: when a `RateLimiter` is in `services`, a registration with no address
   * is refused with `429`, and is never counted under a shared bucket. Default
   * `false`.
   */
  readonly allowMissingClientIp?: boolean | undefined;
}

/**
 * Result of a dynamic registration. The plaintext `clientSecret` (confidential
 * clients only) and `registrationAccessToken` are returned exactly once — both
 * are stored as sha256 digests.
 */
export interface DynamicallyRegisteredOidcClient {
  readonly client: OidcClient;
  /** Absent for public clients (`token_endpoint_auth_method: "none"`). */
  readonly clientSecret?: string;
  /** RFC 7592 registration access token for the management endpoints. */
  readonly registrationAccessToken: string;
}

/** What the HTTP layer needs to know about the registration configuration. */
export interface OidcDynamicRegistrationInfo {
  /** `POST /register` is served (404 otherwise). */
  readonly enabled: boolean;
  /** The RFC 7592 management endpoints are served. */
  readonly management: boolean;
  /** Per-IP rate limit for `POST /register`. */
  readonly rateLimit: RateLimitConfig;
}

/** A parsed `GET /oauth2/authorize` request (snake_case per RFC 6749). */
export interface OidcAuthorizeRequest {
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
export type OidcAuthorizeResult =
  | { readonly type: "code"; readonly redirectTo: string }
  | { readonly type: "consent"; readonly redirectTo: string; readonly consentCode: string }
  | { readonly type: "error"; readonly redirectTo: string; readonly error: string };

/** A parsed `POST /oauth2/token` request (snake_case per RFC 6749). */
export interface OidcTokenRequest {
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
export interface OidcTokenResult {
  readonly accessToken: string;
  readonly tokenType: "Bearer";
  /** Seconds until the access token expires. */
  readonly expiresIn: number;
  readonly refreshToken?: string;
  readonly idToken?: string;
  readonly scope: string;
}

/** A statically configured, implicitly trusted client (consent skipped). */
export interface TrustedOidcClient {
  readonly clientId: string;
  /** Plaintext secret (hashed at service creation); omit for public clients. */
  readonly clientSecret?: Redacted.Redacted<string>;
  readonly name: string;
  readonly redirectUris: readonly string[];
  readonly type?: "web" | "native";
  readonly skipConsent?: boolean;
}

/** Configuration for {@link make}. */
export interface OidcProviderConfig {
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
  readonly trustedClients?: readonly TrustedOidcClient[];
  /**
   * Enable RFC 7591 dynamic client registration (and, unless disabled, the
   * RFC 7592 management endpoints). Omit to keep `POST /register` unmounted.
   */
  readonly dynamicRegistration?: OidcDynamicRegistrationConfig;
}

/**
 * Acts as an OpenID Connect identity provider: client registration (including RFC 7591 dynamic registration), the authorization-code flow with PKCE and consent, the token and userinfo endpoints, and discovery metadata.
 *
 * Requires `OidcClientStore`, `OidcCodeStore`, `OidcConsentStore`, `OidcTokenStore`, `JwtService`, `UserStore` and `IdentifierStore`.
 */
export class OidcProviderService extends Context.Service<
  OidcProviderService,
  {
    /**
     * Register a client application. Generates the `client_id` and — for `web`
     * (confidential) clients — a secret returned in plaintext exactly once.
     * Gate this behind an admin check at the HTTP layer.
     */
    readonly registerClient: (
      input: RegisterOidcClientInput,
      registrarUserId?: string,
    ) => Effect.Effect<RegisteredOidcClient, OidcProviderError | AuthError>;

    /**
     * RFC 7591 dynamic client registration. Validates the metadata, runs the
     * configured policy, and issues a `client_id` (plus a secret for
     * confidential clients) and an RFC 7592 registration access token.
     *
     * Unlike {@link registerClient} this is reachable by anonymous callers, so
     * it is only served when `dynamicRegistration` is configured and is gated
     * by the optional initial access token, the policy hook, and the HTTP
     * layer's per-IP rate limit.
     */
    readonly registerDynamicClient: (
      metadata: OidcClientMetadata,
      options?: { readonly initialAccessToken?: string },
    ) => Effect.Effect<DynamicallyRegisteredOidcClient, OidcRegistrationError | AuthError>;

    /** RFC 7592 read: the client behind a registration access token. */
    readonly readDynamicClient: (
      clientId: string,
      registrationAccessToken: string,
    ) => Effect.Effect<OidcClient, OidcRegistrationError | AuthError>;

    /**
     * RFC 7592 update: replace a dynamically registered client's metadata.
     * The metadata is validated and policy-checked exactly as at registration;
     * the client secret and registration access token are left untouched.
     */
    readonly updateDynamicClient: (
      clientId: string,
      registrationAccessToken: string,
      metadata: OidcClientMetadata,
    ) => Effect.Effect<OidcClient, OidcRegistrationError | AuthError>;

    /** RFC 7592 delete: deregister a dynamically registered client. */
    readonly deleteDynamicClient: (
      clientId: string,
      registrationAccessToken: string,
    ) => Effect.Effect<void, OidcRegistrationError | AuthError>;

    /** Whether (and how) dynamic registration is served. */
    readonly dynamicRegistration: OidcDynamicRegistrationInfo;

    /** Look up a client (trusted config clients first, then the store). */
    readonly getClient: (clientId: string) => Effect.Effect<OidcClient | null, AuthError>;

    /** List registered clients (store-backed only). */
    readonly listClients: () => Effect.Effect<ReadonlyArray<OidcClient>, AuthError>;

    /** Update a registered client. Trusted config clients cannot be updated. */
    readonly updateClient: (
      clientId: string,
      input: UpdateOidcClientInput,
    ) => Effect.Effect<OidcClient, OidcProviderError | AuthError>;

    /** Delete a registered client. */
    readonly deleteClient: (clientId: string) => Effect.Effect<void, OidcProviderError | AuthError>;

    /**
     * Process an authorization request for an authenticated user. Fails with
     * {@link OidcProviderError} only for errors that must NOT redirect back to
     * the client (unknown client, unregistered `redirect_uri`); every other
     * outcome is a redirect (code, consent page, or spec error).
     */
    readonly authorize: (
      user: Types.User,
      request: OidcAuthorizeRequest,
    ) => Effect.Effect<OidcAuthorizeResult, OidcProviderError | AuthError>;

    /**
     * Resolve a pending consent request. Accepting records the consent and
     * issues an authorization code; denying redirects with
     * `error=access_denied`. The `userId` must match the pending request.
     */
    readonly consent: (
      userId: string,
      consentCode: string,
      accept: boolean,
    ) => Effect.Effect<{ readonly redirectTo: string }, OidcProviderError | AuthError>;

    /**
     * Token endpoint: `authorization_code` (with PKCE verification) and
     * `refresh_token` (rotating) grants. Client authentication accepts a
     * secret for confidential clients; public clients must present a PKCE
     * verifier instead.
     */
    readonly token: (
      request: OidcTokenRequest,
    ) => Effect.Effect<OidcTokenResult, OidcTokenError | AuthError>;

    /**
     * Resolve the standard claims for a bearer access token
     * (`sub` always; `email`/`email_verified` with the `email` scope;
     * `name`/`picture` with the `profile` scope).
     */
    readonly userinfo: (
      accessToken: string,
    ) => Effect.Effect<Record<string, unknown>, OidcProviderError | AuthError>;

    /** The OpenID Provider Metadata document (OIDC Discovery). */
    readonly getMetadata: () => Record<string, unknown>;

    /**
     * The OAuth 2.0 Authorization Server Metadata document (RFC 8414), served
     * at `/.well-known/oauth-authorization-server`. This is what MCP clients
     * fetch to discover the registration, authorization, and token endpoints.
     */
    readonly getAuthorizationServerMetadata: () => Record<string, unknown>;

    /**
     * The login page URL for an unauthenticated authorization request, with the
     * original authorize URL attached as `redirect_to` so the app can resume
     * the flow after sign-in.
     */
    readonly loginRedirect: (returnTo: string) => string;
  }
>()("@effect-auth/OidcProviderService") {
  /**
   * Construct a Layer providing this service.
   */
  static readonly layer = (config: OidcProviderConfig) =>
    Layer.effect(OidcProviderService, make(config)).pipe(Layer.provide(PlatformCrypto.layer));
}

// -----------------------------------------------------------------------------
// Helpers
// -----------------------------------------------------------------------------

/** SHA-256 hex digest used for every OIDC secret at rest (tokens, codes, secrets). */
export const hashOidcSecret = hashToken;

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

/** Scopes clients may request when `allowedScopes` isn't configured. */
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

/**
 * Redirect-URI rule for dynamically registered clients: the {@link
 * isAllowedRedirectUri} https/loopback rule, optionally widened with
 * private-use URI schemes (RFC 8252 §7.1), and always rejecting a fragment
 * component (RFC 6749 §3.1.2).
 */
const isAllowedDynamicRedirectUri = (uri: string, extraSchemes: readonly string[]): boolean => {
  let parsed: URL;
  try {
    parsed = new URL(uri);
  } catch {
    return false;
  }
  if (parsed.hash !== "") return false;
  const scheme = parsed.protocol.slice(0, -1).toLowerCase();
  if (extraSchemes.some((s) => s.toLowerCase() === scheme)) return true;
  return isAllowedRedirectUri(uri);
};

/**
 * The OIDC provider configuration an MCP server needs: PKCE enforced for every
 * client, dynamic client registration on, and the RFC 7592 management
 * endpoints available so a client can maintain its own registration.
 *
 * ```ts
 * import assert from "node:assert/strict"
 * import { Redacted } from "effect"
 * import { ClientIP, mcpProviderPreset, OidcProviderService } from "@thomasfosterau/effect-auth"
 *
 * const config = mcpProviderPreset({
 *   issuer: "https://mcp.example.com/api/auth",
 *   loginPage: "https://mcp.example.com/login",
 *   consentPage: "https://mcp.example.com/consent",
 *   dynamicRegistration: {
 *     initialAccessToken: Redacted.make("example-initial-access-token"),
 *     // The same address source as the app's Http.make `trustedProxy`.
 *     trustedProxy: ClientIP.cloudflare,
 *   },
 * })
 *
 * // The preset turns on PKCE and dynamic client management.
 * assert.equal(config.requirePKCE, true)
 * assert.equal(config.dynamicRegistration?.management, true)
 *
 * // The provider layer. Building it also needs the app's OIDC client, code,
 * // token and consent stores, plus its user, identifier and JWT services, so the
 * // layer is constructed here and not built.
 * export const oidcLayer = OidcProviderService.layer(config)
 * ```
 *
 * Everything is overridable: the spread order keeps whatever the caller passes,
 * and `dynamicRegistration` is merged field-by-field so adding a `policy` or an
 * `initialAccessToken` does not drop the preset's defaults.
 */
export const mcpProviderPreset = (config: OidcProviderConfig): OidcProviderConfig => ({
  // MCP clients are public + PKCE; requiring it of confidential clients too
  // costs nothing and closes code-injection on any first-party client.
  requirePKCE: true,
  ...config,
  dynamicRegistration: {
    skipConsent: false,
    management: true,
    ...config.dynamicRegistration,
  },
});

// -----------------------------------------------------------------------------
// Service implementation
// -----------------------------------------------------------------------------

export const make = (
  config: OidcProviderConfig,
): Effect.Effect<
  typeof OidcProviderService.Service,
  ClientAddressConfigError,
  | OidcClientStore
  | OidcCodeStore
  | OidcConsentStore
  | OidcTokenStore
  | UserStore
  | IdentifierStore
  | JwtService
  | Crypto.Crypto
> =>
  Effect.gen(function* () {
    // Build-time check (#388): dynamic registration is rate limited per client
    // address. With no declared address source and no opt-out there is nothing
    // to key the limit on, so fail here, not per request.
    const registration = config.dynamicRegistration;
    if (
      registration !== undefined &&
      registration.trustedProxy === undefined &&
      registration.allowMissingClientIp !== true
    ) {
      return yield* new ClientAddressConfigError({
        message:
          "dynamicRegistration is rate limited per client address, and a Web Request has none unless the app declares a source. " +
          "Set dynamicRegistration.trustedProxy to the source passed to Http.make (for example ClientIP.cloudflare), " +
          "or set dynamicRegistration.allowMissingClientIp: true to accept that address-less registrations are refused.",
      });
    }

    const codeExpiresIn = config.codeExpiresIn ?? 10 * 60 * 1000;
    const accessTokenExpiresIn = config.accessTokenExpiresIn ?? 60 * 60 * 1000;
    const refreshTokenExpiresIn = config.refreshTokenExpiresIn ?? 30 * 24 * 60 * 60 * 1000;
    const allowedScopes = config.allowedScopes ?? DEFAULT_OIDC_SCOPES;
    const dcr = config.dynamicRegistration;
    const dynamicRegistration: OidcDynamicRegistrationInfo = {
      enabled: dcr !== undefined,
      management: dcr !== undefined && (dcr.management ?? true),
      rateLimit: dcr?.rateLimit ?? DEFAULT_OIDC_REGISTRATION_RATE_LIMIT,
    };

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
    const trustedClients = new Map<string, OidcClient>(
      (config.trustedClients ?? []).map((c) => [
        c.clientId,
        {
          clientId: c.clientId,
          ...(c.clientSecret !== undefined && {
            clientSecretHash: hashOidcSecret(Redacted.value(c.clientSecret)),
          }),
          name: c.name,
          redirectUris: c.redirectUris,
          type: c.type ?? "web",
          skipConsent: c.skipConsent ?? true,
          disabled: false,
          metadata: {},
          createdAt: 0,
          updatedAt: 0,
        } satisfies OidcClient,
      ]),
    );

    const clientStore = yield* OidcClientStore;
    const codeStore = yield* OidcCodeStore;
    const consentStore = yield* OidcConsentStore;
    const tokenStore = yield* OidcTokenStore;
    const userStore = yield* UserStore;
    const identifierStore = yield* IdentifierStore;
    const jwt = yield* JwtService;
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
      kind: OidcAuthorizationCode["kind"],
      base: Omit<OidcAuthorizationCode, "codeHash" | "kind" | "expiresAt" | "createdAt">,
    ) =>
      Effect.gen(function* () {
        const value = yield* randomToken();
        const now = Date.now();
        yield* codeStore.create({
          ...base,
          codeHash: hashOidcSecret(value),
          kind,
          expiresAt: now + codeExpiresIn,
          createdAt: now,
        });
        return value;
      });

    /**
     * Build the standard claims for a user, filtered by granted scopes. Email
     * claims resolve the user's email identifier; omitted when none exists.
     */
    const claimsFor = (
      user: Types.User,
      scopes: readonly string[],
    ): Effect.Effect<Record<string, unknown>, AuthError> =>
      Effect.gen(function* () {
        const email = scopes.includes("email")
          ? anyEmail(yield* identifierStore.listByUser(user.id))
          : null;
        return {
          sub: user.id,
          ...(scopes.includes("profile") && {
            ...(user.name !== undefined && { name: user.name }),
            ...(user.image !== undefined && { picture: user.image }),
            updated_at: Math.floor(user.updatedAt.getTime() / 1000),
          }),
          ...(email !== null && {
            email: email.value,
            email_verified: email.verified,
          }),
        };
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
                (e) => new OidcTokenError({ error: "invalid_grant", description: e.message }),
              ),
            );
          if (user === null) {
            return yield* new OidcTokenError({
              error: "invalid_grant",
              description: "Unknown user",
            });
          }
          const signed = yield* jwt
            .sign(user, {
              iss: config.issuer,
              aud: grant.clientId,
              ...(grant.nonce !== undefined && { nonce: grant.nonce }),
              ...(yield* claimsFor(user, grant.scopes)),
            })
            .pipe(
              Effect.catchTag("JwtError", (e) =>
                Effect.fail(new OidcTokenError({ error: "server_error", description: e.message })),
              ),
            );
          idToken = signed.token;
        }

        const accessToken = yield* randomToken();
        yield* tokenStore.create({
          tokenHash: hashOidcSecret(accessToken),
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
            tokenHash: hashOidcSecret(refreshToken),
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
        } satisfies OidcTokenResult;
      });

    /**
     * Authenticate the client for a token request: confidential clients must
     * present their secret; public clients authenticate via PKCE (checked by
     * the grant handling).
     */
    const authenticateClient = (request: OidcTokenRequest) =>
      Effect.gen(function* () {
        if (request.clientId === undefined) {
          return yield* new OidcTokenError({
            error: "invalid_client",
            description: "Missing client_id",
          });
        }
        const client = yield* getClient(request.clientId);
        if (client === null || client.disabled) {
          return yield* new OidcTokenError({
            error: "invalid_client",
            description: "Unknown client",
          });
        }
        if (client.clientSecretHash !== undefined) {
          if (
            request.clientSecret === undefined ||
            !secretEquals(hashOidcSecret(request.clientSecret), client.clientSecretHash)
          ) {
            return yield* new OidcTokenError({
              error: "invalid_client",
              description: "Invalid client credentials",
            });
          }
        }
        return client;
      });

    // --- RFC 7591 / 7592 -----------------------------------------------------

    /** The registration config, or an `access_denied` failure when DCR is off. */
    const requireDynamicRegistration = Effect.suspend(() =>
      dcr === undefined
        ? Effect.fail(
            new OidcRegistrationError({
              error: "access_denied",
              description: "Dynamic client registration is not enabled",
            }),
          )
        : Effect.succeed(dcr),
    );

    /** RFC 7591 §3.1 initial access token, when the deployment requires one. */
    const verifyInitialAccessToken = (token: string | undefined) =>
      Effect.gen(function* () {
        const required = dcr?.initialAccessToken;
        if (required === undefined) return;
        const invalid = new OidcRegistrationError({
          error: "invalid_token",
          description: "A valid initial access token is required to register a client",
        });
        if (token === undefined) return yield* invalid;
        const ok =
          typeof required === "function"
            ? yield* required(token)
            : secretEquals(token, Redacted.value(required));
        if (!ok) return yield* invalid;
      });

    /**
     * Validate RFC 7591 metadata and fill in the spec defaults. Anything the
     * provider cannot honour is rejected rather than silently narrowed, so a
     * client never believes it registered for a grant it will not receive.
     */
    const normalizeMetadata = (
      metadata: OidcClientMetadata,
    ): Effect.Effect<NormalizedOidcClientMetadata, OidcRegistrationError> =>
      Effect.gen(function* () {
        const invalid = (description: string) =>
          new OidcRegistrationError({ error: "invalid_client_metadata", description });

        if (metadata.redirectUris.length === 0) {
          return yield* new OidcRegistrationError({
            error: "invalid_redirect_uri",
            description: "At least one redirect_uri is required",
          });
        }
        const extraSchemes = dcr?.allowedRedirectUriSchemes ?? [];
        for (const uri of metadata.redirectUris) {
          if (!isAllowedDynamicRedirectUri(uri, extraSchemes)) {
            return yield* new OidcRegistrationError({
              error: "invalid_redirect_uri",
              description: `redirect_uri must be https, loopback http, or a registered private-use scheme, without a fragment: ${uri}`,
            });
          }
        }

        // RFC 7591 §2: omitted `token_endpoint_auth_method` means client_secret_basic.
        const authMethod = metadata.tokenEndpointAuthMethod ?? "client_secret_basic";
        if (!(OIDC_TOKEN_ENDPOINT_AUTH_METHODS as readonly string[]).includes(authMethod)) {
          return yield* invalid(`Unsupported token_endpoint_auth_method: ${authMethod}`);
        }

        const grantTypes = metadata.grantTypes ?? ["authorization_code"];
        for (const grant of grantTypes) {
          if (!(OIDC_DYNAMIC_GRANT_TYPES as readonly string[]).includes(grant)) {
            return yield* invalid(`Unsupported grant_type: ${grant}`);
          }
        }
        if (!grantTypes.includes("authorization_code")) {
          return yield* invalid("grant_types must include authorization_code");
        }

        const responseTypes = metadata.responseTypes ?? ["code"];
        for (const responseType of responseTypes) {
          if (!(OIDC_DYNAMIC_RESPONSE_TYPES as readonly string[]).includes(responseType)) {
            return yield* invalid(`Unsupported response_type: ${responseType}`);
          }
        }
        // RFC 7591 §2: the two lists must agree — authorization_code needs `code`.
        if (!responseTypes.includes("code")) {
          return yield* invalid("response_types must include code");
        }

        const scope = metadata.scope ?? dcr?.defaultScope ?? allowedScopes.join(" ");
        const scopes = parseScopes(scope);
        for (const s of scopes) {
          if (!allowedScopes.includes(s)) return yield* invalid(`Unsupported scope: ${s}`);
        }
        if (!scopes.includes("openid")) {
          return yield* invalid("scope must include openid");
        }
        // A refresh_token grant is only reachable with offline_access.
        if (grantTypes.includes("refresh_token") && !scopes.includes("offline_access")) {
          return yield* invalid("the refresh_token grant requires the offline_access scope");
        }

        return {
          redirectUris: metadata.redirectUris,
          tokenEndpointAuthMethod: authMethod as OidcTokenEndpointAuthMethod,
          grantTypes,
          responseTypes,
          clientName: metadata.clientName ?? "Dynamic Client",
          scope: scopes.join(" "),
        } satisfies NormalizedOidcClientMetadata;
      });

    /** Run the registration policy and turn its verdict into a disposition. */
    const applyRegistrationPolicy = (metadata: NormalizedOidcClientMetadata) =>
      Effect.gen(function* () {
        if (dcr?.policy === undefined) return { allow: true } as OidcRegistrationDisposition;
        const verdict = yield* dcr.policy(metadata);
        const disposition: OidcRegistrationDisposition =
          typeof verdict === "boolean" ? { allow: verdict } : verdict;
        if (!disposition.allow) {
          return yield* new OidcRegistrationError({
            // RFC 7591 §3.2.2 has no generic refusal code: a policy that
            // dislikes the metadata reports invalid_client_metadata, and one
            // refusing the caller outright can ask for access_denied (403).
            error: disposition.error ?? "invalid_client_metadata",
            ...(disposition.errorDescription !== undefined && {
              description: disposition.errorDescription,
            }),
          });
        }
        return disposition;
      });

    /**
     * RFC 7592 §2: authenticate a management call with its registration access
     * token. An unknown client is answered exactly like a bad token so the
     * endpoint cannot be used to enumerate client ids.
     */
    const authenticateRegistrationAccess = (clientId: string, token: string) =>
      Effect.gen(function* () {
        const client = yield* clientStore.getByClientId(clientId);
        if (
          client === null ||
          client.registrationAccessTokenHash === undefined ||
          !secretEquals(hashOidcSecret(token), client.registrationAccessTokenHash)
        ) {
          return yield* new OidcRegistrationError({
            error: "invalid_token",
            description: "Invalid registration access token",
          });
        }
        return client;
      });

    /**
     * The RFC 8414 core: the fields an OAuth 2.0 client (an MCP client, say)
     * needs, shared verbatim by the OIDC discovery document.
     *
     * `registration_endpoint` points at the RFC 7591 endpoint once dynamic
     * registration is enabled, and otherwise at the admin-gated
     * `/oauth2/register` — which is all this provider offers to advertise.
     */
    const authorizationServerMetadata = (): Record<string, unknown> => ({
      issuer: config.issuer,
      authorization_endpoint: `${config.issuer}/oauth2/authorize`,
      token_endpoint: `${config.issuer}/oauth2/token`,
      jwks_uri: `${config.issuer}/.well-known/jwks.json`,
      registration_endpoint: dynamicRegistration.enabled
        ? `${config.issuer}/register`
        : `${config.issuer}/oauth2/register`,
      scopes_supported: [...allowedScopes],
      response_types_supported: ["code"],
      response_modes_supported: ["query"],
      grant_types_supported: ["authorization_code", "refresh_token"],
      token_endpoint_auth_methods_supported: [...OIDC_TOKEN_ENDPOINT_AUTH_METHODS],
      code_challenge_methods_supported: ["S256"],
    });

    return {
      dynamicRegistration,

      registerDynamicClient: Effect.fn("OidcProviderService.registerDynamicClient")(
        (metadata: OidcClientMetadata, options?: { readonly initialAccessToken?: string }) =>
          Effect.gen(function* () {
            yield* requireDynamicRegistration;
            yield* verifyInitialAccessToken(options?.initialAccessToken);
            const normalized = yield* normalizeMetadata(metadata);
            const disposition = yield* applyRegistrationPolicy(normalized);

            const isPublic = normalized.tokenEndpointAuthMethod === "none";
            const clientSecret = isPublic ? undefined : yield* randomToken();
            const registrationAccessToken = yield* randomToken();
            const clientId = yield* randomClientId();
            const now = Date.now();
            const client = yield* clientStore.create({
              clientId,
              ...(clientSecret !== undefined && {
                clientSecretHash: hashOidcSecret(clientSecret),
              }),
              name: normalized.clientName,
              redirectUris: normalized.redirectUris,
              // Public clients are `native`: the authorize endpoint then
              // requires PKCE and the token endpoint refuses a code without it.
              type: isPublic ? "native" : "web",
              skipConsent: disposition.skipConsent ?? dcr?.skipConsent ?? false,
              disabled: false,
              metadata: {},
              createdAt: now,
              updatedAt: now,
              registrationAccessTokenHash: hashOidcSecret(registrationAccessToken),
              tokenEndpointAuthMethod: normalized.tokenEndpointAuthMethod,
              grantTypes: normalized.grantTypes,
              responseTypes: normalized.responseTypes,
              scope: normalized.scope,
              dynamicallyRegistered: true,
            });
            return {
              client,
              ...(clientSecret !== undefined && { clientSecret }),
              registrationAccessToken,
            } satisfies DynamicallyRegisteredOidcClient;
          }).pipe(Effect.withSpan(Obs.spanNames.oidcRegisterDynamicClient)),
      ),

      readDynamicClient: Effect.fn("OidcProviderService.readDynamicClient")(function* (
        clientId: string,
        registrationAccessToken: string,
      ) {
        yield* requireDynamicRegistration;
        return yield* authenticateRegistrationAccess(clientId, registrationAccessToken);
      }),

      updateDynamicClient: Effect.fn("OidcProviderService.updateDynamicClient")(function* (
        clientId: string,
        registrationAccessToken: string,
        metadata: OidcClientMetadata,
      ) {
        yield* requireDynamicRegistration;
        const existing = yield* authenticateRegistrationAccess(clientId, registrationAccessToken);
        const normalized = yield* normalizeMetadata(metadata);
        const disposition = yield* applyRegistrationPolicy(normalized);
        // RFC 7592 §2.2: the client cannot change its own authentication
        // method (that would let a public client mint itself a secret, or a
        // confidential one drop to `none`), so the registered method stands.
        if (
          existing.tokenEndpointAuthMethod !== undefined &&
          normalized.tokenEndpointAuthMethod !== existing.tokenEndpointAuthMethod
        ) {
          return yield* new OidcRegistrationError({
            error: "invalid_client_metadata",
            description: "token_endpoint_auth_method cannot be changed after registration",
          });
        }
        return yield* clientStore.update({
          ...existing,
          name: normalized.clientName,
          redirectUris: normalized.redirectUris,
          grantTypes: normalized.grantTypes,
          responseTypes: normalized.responseTypes,
          scope: normalized.scope,
          ...(disposition.skipConsent !== undefined && { skipConsent: disposition.skipConsent }),
          updatedAt: Date.now(),
        });
      }),

      deleteDynamicClient: Effect.fn("OidcProviderService.deleteDynamicClient")(function* (
        clientId: string,
        registrationAccessToken: string,
      ) {
        yield* requireDynamicRegistration;
        const client = yield* authenticateRegistrationAccess(clientId, registrationAccessToken);
        yield* clientStore.delete(client.clientId);
      }),

      registerClient: Effect.fn("OidcProviderService.registerClient")(function* (
        input: RegisterOidcClientInput,
        registrarUserId?: string,
      ) {
        if (input.redirectUris.length === 0) {
          return yield* new OidcProviderError({
            message: "At least one redirect URI is required",
          });
        }
        for (const uri of input.redirectUris) {
          if (!isAllowedRedirectUri(uri)) {
            return yield* new OidcProviderError({
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
          ...(clientSecret !== undefined && { clientSecretHash: hashOidcSecret(clientSecret) }),
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
        } satisfies RegisteredOidcClient;
      }),

      getClient: Effect.fn("OidcProviderService.getClient")(getClient),

      listClients: Effect.fn("OidcProviderService.listClients")(function* () {
        return yield* clientStore.list();
      }),

      updateClient: Effect.fn("OidcProviderService.updateClient")(function* (
        clientId: string,
        input: UpdateOidcClientInput,
      ) {
        if (trustedClients.has(clientId)) {
          return yield* new OidcProviderError({
            message: "Trusted clients are configured statically and cannot be updated",
          });
        }
        const existing = yield* clientStore.getByClientId(clientId);
        if (existing === null) {
          return yield* new OidcProviderError({ message: "Client not found" });
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

      deleteClient: Effect.fn("OidcProviderService.deleteClient")(function* (clientId: string) {
        const existing = yield* clientStore.getByClientId(clientId);
        if (existing === null) {
          return yield* new OidcProviderError({ message: "Client not found" });
        }
        yield* clientStore.delete(clientId);
      }),

      authorize: Effect.fn("OidcProviderService.authorize")(
        (user: Types.User, request: OidcAuthorizeRequest) =>
          Effect.gen(function* () {
            // Unknown client / unregistered redirect_uri: NEVER redirect (RFC 6749 §4.1.2.1).
            const client = yield* getClient(request.clientId);
            if (client === null || client.disabled) {
              return yield* new OidcProviderError({ message: "Unknown client" });
            }
            if (!client.redirectUris.includes(request.redirectUri)) {
              return yield* new OidcProviderError({ message: "Unregistered redirect_uri" });
            }

            const errorRedirect = (error: string): OidcAuthorizeResult => ({
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
            // A dynamically registered client is held to the response_types it
            // registered for; statically registered clients carry none.
            if (
              client.responseTypes !== undefined &&
              !client.responseTypes.includes(request.responseType)
            ) {
              return errorRedirect("unsupported_response_type");
            }

            const scopes = parseScopes(request.scope);
            if (!scopes.includes("openid") || scopes.some((s) => !allowedScopes.includes(s))) {
              return errorRedirect("invalid_scope");
            }
            // Likewise for the scopes it registered for (RFC 7591 §2 `scope`).
            if (client.scope !== undefined) {
              const registered = parseScopes(client.scope);
              if (scopes.some((s) => !registered.includes(s))) {
                return errorRedirect("invalid_scope");
              }
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
              } satisfies OidcAuthorizeResult;
            }

            const code = yield* issueCode("authorization_code", codeFields);
            return {
              type: "code",
              redirectTo: buildRedirect(request.redirectUri, {
                code,
                ...(request.state !== undefined && { state: request.state }),
              }),
            } satisfies OidcAuthorizeResult;
          }).pipe(Effect.withSpan(Obs.spanNames.oidcAuthorize)),
      ),

      consent: Effect.fn("OidcProviderService.consent")(
        (userId: string, consentCode: string, accept: boolean) =>
          Effect.gen(function* () {
            const pending = yield* codeStore.get(hashOidcSecret(consentCode));
            if (
              pending === null ||
              pending.kind !== "pending_consent" ||
              pending.userId !== userId ||
              Date.now() > pending.expiresAt
            ) {
              return yield* new OidcProviderError({
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
          }).pipe(Effect.withSpan(Obs.spanNames.oidcConsent)),
      ),

      token: Effect.fn("OidcProviderService.token")((request: OidcTokenRequest) =>
        Effect.gen(function* () {
          const client = yield* authenticateClient(request);

          // RFC 6749 §5.2: a client may only use the grants it registered for.
          // `grantTypes` is set by dynamic registration only — statically and
          // admin-registered clients keep access to every supported grant.
          if (client.grantTypes !== undefined && !client.grantTypes.includes(request.grantType)) {
            return yield* new OidcTokenError({
              error: "unauthorized_client",
              description: `The client is not registered for the ${request.grantType} grant`,
            });
          }

          if (request.grantType === "authorization_code") {
            if (request.code === undefined) {
              return yield* new OidcTokenError({
                error: "invalid_request",
                description: "Missing code",
              });
            }
            const record = yield* codeStore.get(hashOidcSecret(request.code));
            if (
              record === null ||
              record.kind !== "authorization_code" ||
              record.clientId !== client.clientId
            ) {
              return yield* new OidcTokenError({ error: "invalid_grant" });
            }
            // Single use: burn the code before any further checks so a replay
            // (even with corrected parameters) always fails.
            yield* codeStore.delete(record.codeHash);
            if (Date.now() > record.expiresAt) {
              return yield* new OidcTokenError({
                error: "invalid_grant",
                description: "Code expired",
              });
            }
            if (request.redirectUri !== record.redirectUri) {
              return yield* new OidcTokenError({
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
                return yield* new OidcTokenError({
                  error: "invalid_grant",
                  description: "PKCE verification failed",
                });
              }
            } else if (client.clientSecretHash === undefined) {
              // Public client without PKCE: never issue tokens.
              return yield* new OidcTokenError({
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
              return yield* new OidcTokenError({
                error: "invalid_request",
                description: "Missing refresh_token",
              });
            }

            pruneConsumed();
            const presentedHash = hashOidcSecret(request.refreshToken);
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
              return yield* new OidcTokenError({ error: "invalid_grant" });
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
              return yield* new OidcTokenError({
                error: "invalid_grant",
                description: "Refresh token expired",
              });
            }

            // RFC 6749 §6: client may request a strict subset of original scopes.
            let effectiveScopes = record.scopes;
            if (request.scope !== undefined) {
              const requested = parseScopes(request.scope);
              if (requested.some((s) => !record.scopes.includes(s))) {
                return yield* new OidcTokenError({
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

          return yield* new OidcTokenError({ error: "unsupported_grant_type" });
        }).pipe(
          Effect.withSpan(Obs.spanNames.oidcToken, { attributes: { grant: request.grantType } }),
          Effect.tap(() => Obs.recordOidcTokenRequest(request.grantType, "success")),
          Effect.tapError(() => Obs.recordOidcTokenRequest(request.grantType, "failure")),
        ),
      ),

      userinfo: Effect.fn("OidcProviderService.userinfo")((accessToken: string) =>
        Effect.gen(function* () {
          const record = yield* tokenStore.get(hashOidcSecret(accessToken));
          if (record === null || record.kind !== "access" || Date.now() > record.expiresAt) {
            return yield* new OidcProviderError({ message: "Invalid or expired access token" });
          }
          const user = yield* userStore
            .get(record.userId)
            .pipe(
              Effect.mapError(
                () => new OidcProviderError({ message: "Invalid or expired access token" }),
              ),
            );
          if (user === null) {
            return yield* new OidcProviderError({ message: "Invalid or expired access token" });
          }
          return yield* claimsFor(user, record.scopes);
        }).pipe(Effect.withSpan(Obs.spanNames.oidcUserinfo)),
      ),

      getMetadata: () => ({
        ...authorizationServerMetadata(),
        userinfo_endpoint: `${config.issuer}/oauth2/userinfo`,
        end_session_endpoint: `${config.issuer}/oauth2/logout`,
        subject_types_supported: ["public"],
        id_token_signing_alg_values_supported: ["ES256", "EdDSA"],
        claims_supported: ["sub", "email", "email_verified", "name", "picture", "updated_at"],
      }),

      getAuthorizationServerMetadata: authorizationServerMetadata,

      loginRedirect: (returnTo: string) =>
        buildRedirect(config.loginPage, { redirect_to: returnTo }),
    };
  });
