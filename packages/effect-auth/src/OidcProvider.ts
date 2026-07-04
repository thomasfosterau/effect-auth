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
import { Context, Data, Effect, Layer } from "effect";
import * as crypto from "node:crypto";
import type { AuthError } from "./Errors.js";
import { JwtService, JwtKeyStore } from "./Jwt.js";
import { UserStore } from "./Session.js";
import { hashToken } from "./TokenHash.js";
import type * as Types from "./Types.js";

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
}

/** Persistent registry of OIDC clients. */
export interface OidcClientStoreShape {
  readonly create: (client: OidcClient) => Effect.Effect<OidcClient, AuthError>;
  readonly getByClientId: (clientId: string) => Effect.Effect<OidcClient | null, AuthError>;
  readonly update: (client: OidcClient) => Effect.Effect<OidcClient, AuthError>;
  readonly delete: (clientId: string) => Effect.Effect<void, AuthError>;
  readonly list: () => Effect.Effect<ReadonlyArray<OidcClient>, AuthError>;
}

export class OidcClientStore extends Context.Service<OidcClientStore, OidcClientStoreShape>()(
  "@effect-auth/OidcClientStore",
) {}

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
export interface OidcCodeStoreShape {
  readonly create: (code: OidcAuthorizationCode) => Effect.Effect<OidcAuthorizationCode, AuthError>;
  readonly get: (codeHash: string) => Effect.Effect<OidcAuthorizationCode | null, AuthError>;
  readonly delete: (codeHash: string) => Effect.Effect<void, AuthError>;
}

export class OidcCodeStore extends Context.Service<OidcCodeStore, OidcCodeStoreShape>()(
  "@effect-auth/OidcCodeStore",
) {}

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
}

/** Store for issued access and refresh tokens. */
export interface OidcTokenStoreShape {
  readonly create: (token: OidcToken) => Effect.Effect<OidcToken, AuthError>;
  readonly get: (tokenHash: string) => Effect.Effect<OidcToken | null, AuthError>;
  readonly delete: (tokenHash: string) => Effect.Effect<void, AuthError>;
}

export class OidcTokenStore extends Context.Service<OidcTokenStore, OidcTokenStoreShape>()(
  "@effect-auth/OidcTokenStore",
) {}

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
export interface OidcConsentStoreShape {
  readonly get: (userId: string, clientId: string) => Effect.Effect<OidcConsent | null, AuthError>;
  readonly upsert: (consent: OidcConsent) => Effect.Effect<OidcConsent, AuthError>;
  readonly delete: (userId: string, clientId: string) => Effect.Effect<void, AuthError>;
}

export class OidcConsentStore extends Context.Service<OidcConsentStore, OidcConsentStoreShape>()(
  "@effect-auth/OidcConsentStore",
) {}

// -----------------------------------------------------------------------------
// Service types
// -----------------------------------------------------------------------------

/** Input to {@link OidcProviderServiceShape.registerClient}. */
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

/** Fields updatable via {@link OidcProviderServiceShape.updateClient}. */
export interface UpdateOidcClientInput {
  readonly name?: string;
  readonly redirectUris?: readonly string[];
  readonly skipConsent?: boolean;
  readonly disabled?: boolean;
  readonly metadata?: Record<string, unknown>;
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
  readonly clientSecret?: string;
  readonly name: string;
  readonly redirectUris: readonly string[];
  readonly type?: "web" | "native";
  readonly skipConsent?: boolean;
}

/** Configuration for {@link makeOidcProviderService}. */
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
}

export interface OidcProviderServiceShape {
  /**
   * Register a client application. Generates the `client_id` and — for `web`
   * (confidential) clients — a secret returned in plaintext exactly once.
   * Gate this behind an admin check at the HTTP layer.
   */
  readonly registerClient: (
    input: RegisterOidcClientInput,
    registrarUserId?: string,
  ) => Effect.Effect<RegisteredOidcClient, OidcProviderError | AuthError, OidcClientStore>;

  /** Look up a client (trusted config clients first, then the store). */
  readonly getClient: (
    clientId: string,
  ) => Effect.Effect<OidcClient | null, AuthError, OidcClientStore>;

  /** List registered clients (store-backed only). */
  readonly listClients: () => Effect.Effect<ReadonlyArray<OidcClient>, AuthError, OidcClientStore>;

  /** Update a registered client. Trusted config clients cannot be updated. */
  readonly updateClient: (
    clientId: string,
    input: UpdateOidcClientInput,
  ) => Effect.Effect<OidcClient, OidcProviderError | AuthError, OidcClientStore>;

  /** Delete a registered client. */
  readonly deleteClient: (
    clientId: string,
  ) => Effect.Effect<void, OidcProviderError | AuthError, OidcClientStore>;

  /**
   * Process an authorization request for an authenticated user. Fails with
   * {@link OidcProviderError} only for errors that must NOT redirect back to
   * the client (unknown client, unregistered `redirect_uri`); every other
   * outcome is a redirect (code, consent page, or spec error).
   */
  readonly authorize: (
    user: Types.User,
    request: OidcAuthorizeRequest,
  ) => Effect.Effect<
    OidcAuthorizeResult,
    OidcProviderError | AuthError,
    OidcClientStore | OidcCodeStore | OidcConsentStore
  >;

  /**
   * Resolve a pending consent request. Accepting records the consent and
   * issues an authorization code; denying redirects with
   * `error=access_denied`. The `userId` must match the pending request.
   */
  readonly consent: (
    userId: string,
    consentCode: string,
    accept: boolean,
  ) => Effect.Effect<
    { readonly redirectTo: string },
    OidcProviderError | AuthError,
    OidcCodeStore | OidcConsentStore
  >;

  /**
   * Token endpoint: `authorization_code` (with PKCE verification) and
   * `refresh_token` (rotating) grants. Client authentication accepts a
   * secret for confidential clients; public clients must present a PKCE
   * verifier instead.
   */
  readonly token: (
    request: OidcTokenRequest,
  ) => Effect.Effect<
    OidcTokenResult,
    OidcTokenError | AuthError,
    OidcClientStore | OidcCodeStore | OidcTokenStore | UserStore | JwtService | JwtKeyStore
  >;

  /**
   * Resolve the standard claims for a bearer access token
   * (`sub` always; `email`/`email_verified` with the `email` scope;
   * `name`/`picture` with the `profile` scope).
   */
  readonly userinfo: (
    accessToken: string,
  ) => Effect.Effect<
    Record<string, unknown>,
    OidcProviderError | AuthError,
    OidcTokenStore | UserStore
  >;

  /** The OpenID Provider Metadata document (RFC 8414 / OIDC Discovery). */
  readonly getMetadata: () => Record<string, unknown>;

  /**
   * The login page URL for an unauthenticated authorization request, with the
   * original authorize URL attached as `redirect_to` so the app can resume
   * the flow after sign-in.
   */
  readonly loginRedirect: (returnTo: string) => string;
}

export class OidcProviderService extends Context.Service<
  OidcProviderService,
  OidcProviderServiceShape
>()("@effect-auth/OidcProviderService") {
  /**
   * Construct a Layer providing this service.
   */
  static readonly layer = (config: OidcProviderConfig) =>
    Layer.effect(OidcProviderService, makeOidcProviderService(config));
}

// -----------------------------------------------------------------------------
// Helpers
// -----------------------------------------------------------------------------

/** SHA-256 hex digest used for every OIDC secret at rest (tokens, codes, secrets). */
export const hashOidcSecret = hashToken;

/** Constant-time equality of two strings via their SHA-256 digests. */
const secretEquals = (a: string, b: string): boolean =>
  crypto.timingSafeEqual(
    crypto.createHash("sha256").update(a).digest(),
    crypto.createHash("sha256").update(b).digest(),
  );

const randomToken = (): string => crypto.randomBytes(32).toString("base64url");

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

// -----------------------------------------------------------------------------
// Service implementation
// -----------------------------------------------------------------------------

export const makeOidcProviderService = (
  config: OidcProviderConfig,
): Effect.Effect<OidcProviderServiceShape, never> => {
  const codeExpiresIn = config.codeExpiresIn ?? 10 * 60 * 1000;
  const accessTokenExpiresIn = config.accessTokenExpiresIn ?? 60 * 60 * 1000;
  const refreshTokenExpiresIn = config.refreshTokenExpiresIn ?? 30 * 24 * 60 * 60 * 1000;
  const allowedScopes = config.allowedScopes ?? DEFAULT_OIDC_SCOPES;

  /** Trusted config clients, normalized to the stored shape (secret hashed). */
  const trustedClients = new Map<string, OidcClient>(
    (config.trustedClients ?? []).map((c) => [
      c.clientId,
      {
        clientId: c.clientId,
        ...(c.clientSecret !== undefined && { clientSecretHash: hashOidcSecret(c.clientSecret) }),
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

  const getClient = (clientId: string) =>
    Effect.gen(function* () {
      const trusted = trustedClients.get(clientId);
      if (trusted !== undefined) return trusted;
      const store = yield* OidcClientStore;
      return yield* store.getByClientId(clientId);
    });

  /** Create + persist an authorization-code (or pending-consent) record. */
  const issueCode = (
    kind: OidcAuthorizationCode["kind"],
    base: Omit<OidcAuthorizationCode, "codeHash" | "kind" | "expiresAt" | "createdAt">,
  ) =>
    Effect.gen(function* () {
      const store = yield* OidcCodeStore;
      const value = randomToken();
      const now = Date.now();
      yield* store.create({
        ...base,
        codeHash: hashOidcSecret(value),
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
  }) =>
    Effect.gen(function* () {
      const tokenStore = yield* OidcTokenStore;
      const userStore = yield* UserStore;
      const now = Date.now();

      const accessToken = randomToken();
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
        refreshToken = randomToken();
        yield* tokenStore.create({
          tokenHash: hashOidcSecret(refreshToken),
          kind: "refresh",
          clientId: grant.clientId,
          userId: grant.userId,
          scopes: grant.scopes,
          expiresAt: now + refreshTokenExpiresIn,
          createdAt: now,
        });
      }

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
          return yield* new OidcTokenError({ error: "invalid_grant", description: "Unknown user" });
        }
        const jwt = yield* JwtService;
        const signed = yield* jwt
          .sign(user, {
            iss: config.issuer,
            aud: grant.clientId,
            ...(grant.nonce !== undefined && { nonce: grant.nonce }),
            ...claimsFor(user, grant.scopes),
          })
          .pipe(
            Effect.catchTag("JwtError", (e) =>
              Effect.fail(new OidcTokenError({ error: "server_error", description: e.message })),
            ),
          );
        idToken = signed.token;
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

  return Effect.succeed({
    registerClient: (input, registrarUserId) =>
      Effect.gen(function* () {
        const store = yield* OidcClientStore;
        if (input.redirectUris.length === 0) {
          return yield* new OidcProviderError({
            message: "At least one redirect URI is required",
          });
        }
        for (const uri of input.redirectUris) {
          if (!URL.canParse(uri)) {
            return yield* new OidcProviderError({ message: `Invalid redirect URI: ${uri}` });
          }
        }
        const type = input.type ?? "web";
        const clientSecret = type === "web" ? randomToken() : undefined;
        const now = Date.now();
        const client = yield* store.create({
          clientId: crypto.randomBytes(16).toString("hex"),
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

    getClient,

    listClients: () =>
      Effect.gen(function* () {
        const store = yield* OidcClientStore;
        return yield* store.list();
      }),

    updateClient: (clientId, input) =>
      Effect.gen(function* () {
        const store = yield* OidcClientStore;
        if (trustedClients.has(clientId)) {
          return yield* new OidcProviderError({
            message: "Trusted clients are configured statically and cannot be updated",
          });
        }
        const existing = yield* store.getByClientId(clientId);
        if (existing === null) {
          return yield* new OidcProviderError({ message: "Client not found" });
        }
        return yield* store.update({
          ...existing,
          ...(input.name !== undefined && { name: input.name }),
          ...(input.redirectUris !== undefined && { redirectUris: input.redirectUris }),
          ...(input.skipConsent !== undefined && { skipConsent: input.skipConsent }),
          ...(input.disabled !== undefined && { disabled: input.disabled }),
          ...(input.metadata !== undefined && { metadata: input.metadata }),
          updatedAt: Date.now(),
        });
      }),

    deleteClient: (clientId) =>
      Effect.gen(function* () {
        const store = yield* OidcClientStore;
        const existing = yield* store.getByClientId(clientId);
        if (existing === null) {
          return yield* new OidcProviderError({ message: "Client not found" });
        }
        yield* store.delete(clientId);
      }),

    authorize: (user, request) =>
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
          const consentStore = yield* OidcConsentStore;
          const existing = yield* consentStore.get(user.id, client.clientId);
          if (existing !== null && scopes.every((s) => existing.scopes.includes(s))) {
            consentNeeded = false;
          }
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
      }),

    consent: (userId, consentCode, accept) =>
      Effect.gen(function* () {
        const codeStore = yield* OidcCodeStore;
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

        const consentStore = yield* OidcConsentStore;
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

        const { codeHash: _hash, kind: _kind, expiresAt: _e, createdAt: _c, ...fields } = pending;
        const code = yield* issueCode("authorization_code", fields);
        return {
          redirectTo: buildRedirect(pending.redirectUri, {
            code,
            ...(pending.state !== undefined && { state: pending.state }),
          }),
        };
      }),

    token: (request) =>
      Effect.gen(function* () {
        const client = yield* authenticateClient(request);
        const codeStore = yield* OidcCodeStore;
        const tokenStore = yield* OidcTokenStore;

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
            if (
              request.codeVerifier === undefined ||
              !secretEquals(
                crypto.createHash("sha256").update(request.codeVerifier).digest("base64url"),
                record.codeChallenge,
              )
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
          const record = yield* tokenStore.get(hashOidcSecret(request.refreshToken));
          if (record === null || record.kind !== "refresh" || record.clientId !== client.clientId) {
            return yield* new OidcTokenError({ error: "invalid_grant" });
          }
          // Rotation: the presented refresh token is consumed either way.
          yield* tokenStore.delete(record.tokenHash);
          if (Date.now() > record.expiresAt) {
            return yield* new OidcTokenError({
              error: "invalid_grant",
              description: "Refresh token expired",
            });
          }
          return yield* issueTokens({
            clientId: client.clientId,
            userId: record.userId,
            scopes: record.scopes,
          });
        }

        return yield* new OidcTokenError({ error: "unsupported_grant_type" });
      }),

    userinfo: (accessToken) =>
      Effect.gen(function* () {
        const tokenStore = yield* OidcTokenStore;
        const userStore = yield* UserStore;
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
        return claimsFor(user, record.scopes);
      }),

    getMetadata: () => ({
      issuer: config.issuer,
      authorization_endpoint: `${config.issuer}/oauth2/authorize`,
      token_endpoint: `${config.issuer}/oauth2/token`,
      userinfo_endpoint: `${config.issuer}/oauth2/userinfo`,
      jwks_uri: `${config.issuer}/.well-known/jwks.json`,
      scopes_supported: [...allowedScopes],
      response_types_supported: ["code"],
      response_modes_supported: ["query"],
      grant_types_supported: ["authorization_code", "refresh_token"],
      subject_types_supported: ["public"],
      id_token_signing_alg_values_supported: ["ES256", "EdDSA"],
      token_endpoint_auth_methods_supported: ["client_secret_basic", "client_secret_post", "none"],
      code_challenge_methods_supported: ["S256"],
      claims_supported: ["sub", "email", "email_verified", "name", "picture", "updated_at"],
    }),

    loginRedirect: (returnTo) => buildRedirect(config.loginPage, { redirect_to: returnTo }),
  } satisfies OidcProviderServiceShape);
};
