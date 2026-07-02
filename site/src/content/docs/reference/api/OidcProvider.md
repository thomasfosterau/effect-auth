---
title: "OidcProvider"
description: "API reference for the OidcProvider module."
---

## OidcProvider overview

OIDC Provider — act as an OpenID Connect identity provider.

Mirrors better-auth's `oidc-provider` plugin: register client applications,
run the authorization-code flow (with PKCE), handle consent, and issue
opaque access/refresh tokens plus signed `id_token`s so third-party apps can
federate sign-in to this server.

The `id_token` is signed with the {@link module:jwt} `JwtService`, sharing
its signing keys — the JWKS published at `/.well-known/jwks.json` (or
`GET /jwks`) verifies both plain user JWTs and OIDC `id_token`s.

Secrets at rest: client secrets, authorization codes, and access/refresh
tokens are stored only as sha256 hex digests — lookups by exact digest are
inherently timing-safe, and secret comparison re-hashes both sides before a
`crypto.timingSafeEqual`.

---

<h2 class="text-delta">Table of contents</h2>

- [utils](#utils)
  - [DEFAULT_OIDC_SCOPES](#default_oidc_scopes)
  - [OidcAuthorizationCode (interface)](#oidcauthorizationcode-interface)
  - [OidcAuthorizeRequest (interface)](#oidcauthorizerequest-interface)
  - [OidcAuthorizeResult (type alias)](#oidcauthorizeresult-type-alias)
  - [OidcClient (interface)](#oidcclient-interface)
  - [OidcClientStore](#oidcclientstore)
  - [OidcClientStore (interface)](#oidcclientstore-interface)
  - [OidcClientStoreTag (class)](#oidcclientstoretag-class)
  - [OidcCodeStore](#oidccodestore)
  - [OidcCodeStore (interface)](#oidccodestore-interface)
  - [OidcCodeStoreTag (class)](#oidccodestoretag-class)
  - [OidcConsent (interface)](#oidcconsent-interface)
  - [OidcConsentStore](#oidcconsentstore)
  - [OidcConsentStore (interface)](#oidcconsentstore-interface)
  - [OidcConsentStoreTag (class)](#oidcconsentstoretag-class)
  - [OidcProviderConfig (interface)](#oidcproviderconfig-interface)
  - [OidcProviderError (class)](#oidcprovidererror-class)
  - [OidcProviderService](#oidcproviderservice)
  - [OidcProviderService (interface)](#oidcproviderservice-interface)
  - [OidcProviderServiceLayer](#oidcproviderservicelayer)
  - [OidcProviderServiceTag (class)](#oidcproviderservicetag-class)
  - [OidcToken (interface)](#oidctoken-interface)
  - [OidcTokenError (class)](#oidctokenerror-class)
  - [OidcTokenRequest (interface)](#oidctokenrequest-interface)
  - [OidcTokenResult (interface)](#oidctokenresult-interface)
  - [OidcTokenStore](#oidctokenstore)
  - [OidcTokenStore (interface)](#oidctokenstore-interface)
  - [OidcTokenStoreTag (class)](#oidctokenstoretag-class)
  - [RegisterOidcClientInput (interface)](#registeroidcclientinput-interface)
  - [RegisteredOidcClient (interface)](#registeredoidcclient-interface)
  - [TrustedOidcClient (interface)](#trustedoidcclient-interface)
  - [UpdateOidcClientInput (interface)](#updateoidcclientinput-interface)
  - [hashOidcSecret](#hashoidcsecret)
  - [makeOidcProviderService](#makeoidcproviderservice)

---

# utils

## DEFAULT_OIDC_SCOPES

**Signature**

```ts
export declare const DEFAULT_OIDC_SCOPES: readonly ["openid", "profile", "email", "offline_access"];
```

## OidcAuthorizationCode (interface)

A short-lived authorization artifact: either an issued authorization code
(`kind: "authorization_code"`) or a pending consent request
(`kind: "pending_consent"`), keyed by the sha256 hex digest of the
user-visible value.

**Signature**

```ts
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
```

## OidcAuthorizeRequest (interface)

A parsed `GET /oauth2/authorize` request (snake_case per RFC 6749).

**Signature**

```ts
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
```

## OidcAuthorizeResult (type alias)

Outcome of an authorization request. All variants carry a `redirectTo` URL
the HTTP layer answers with a `302`:

- `code`: success — `redirect_uri?code=...&state=...`
- `consent`: user consent required — the configured consent page, with a
  `consent_code` to post back to the consent endpoint
- `error`: a spec-level error redirected to the client per RFC 6749 —
  `redirect_uri?error=...&state=...`

**Signature**

```ts
export type OidcAuthorizeResult =
  | { readonly type: "code"; readonly redirectTo: string }
  | { readonly type: "consent"; readonly redirectTo: string; readonly consentCode: string }
  | { readonly type: "error"; readonly redirectTo: string; readonly error: string };
```

## OidcClient (interface)

A registered OAuth2/OIDC client application.

**Signature**

```ts
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
```

## OidcClientStore

**Signature**

```ts
export declare const OidcClientStore: typeof OidcClientStoreTag;
```

## OidcClientStore (interface)

Persistent registry of OIDC clients.

**Signature**

```ts
export interface OidcClientStore {
  readonly create: (client: OidcClient) => Effect.Effect<OidcClient, AuthError>;
  readonly getByClientId: (clientId: string) => Effect.Effect<OidcClient | null, AuthError>;
  readonly update: (client: OidcClient) => Effect.Effect<OidcClient, AuthError>;
  readonly delete: (clientId: string) => Effect.Effect<void, AuthError>;
  readonly list: () => Effect.Effect<ReadonlyArray<OidcClient>, AuthError>;
}
```

## OidcClientStoreTag (class)

**Signature**

```ts
export declare class OidcClientStoreTag
```

## OidcCodeStore

**Signature**

```ts
export declare const OidcCodeStore: typeof OidcCodeStoreTag;
```

## OidcCodeStore (interface)

Ephemeral store for authorization codes and pending consent requests.

**Signature**

```ts
export interface OidcCodeStore {
  readonly create: (code: OidcAuthorizationCode) => Effect.Effect<OidcAuthorizationCode, AuthError>;
  readonly get: (codeHash: string) => Effect.Effect<OidcAuthorizationCode | null, AuthError>;
  readonly delete: (codeHash: string) => Effect.Effect<void, AuthError>;
}
```

## OidcCodeStoreTag (class)

**Signature**

```ts
export declare class OidcCodeStoreTag
```

## OidcConsent (interface)

A user's recorded consent for a client (the union of granted scopes).

**Signature**

```ts
export interface OidcConsent {
  readonly userId: string;
  readonly clientId: string;
  readonly scopes: readonly string[];
  /** Epoch milliseconds. */
  readonly createdAt: number;
  readonly updatedAt: number;
}
```

## OidcConsentStore

**Signature**

```ts
export declare const OidcConsentStore: typeof OidcConsentStoreTag;
```

## OidcConsentStore (interface)

Store for recorded user consents.

**Signature**

```ts
export interface OidcConsentStore {
  readonly get: (userId: string, clientId: string) => Effect.Effect<OidcConsent | null, AuthError>;
  readonly upsert: (consent: OidcConsent) => Effect.Effect<OidcConsent, AuthError>;
  readonly delete: (userId: string, clientId: string) => Effect.Effect<void, AuthError>;
}
```

## OidcConsentStoreTag (class)

**Signature**

```ts
export declare class OidcConsentStoreTag
```

## OidcProviderConfig (interface)

Configuration for {@link makeOidcProviderService}.

**Signature**

```ts
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
```

## OidcProviderError (class)

Failure to register a client or process an authorization request.

**Signature**

```ts
export declare class OidcProviderError
```

## OidcProviderService

**Signature**

```ts
export declare const OidcProviderService: typeof OidcProviderServiceTag;
```

## OidcProviderService (interface)

**Signature**

```ts
export interface OidcProviderService {
  /**
   * Register a client application. Generates the `client_id` and — for `web`
   * (confidential) clients — a secret returned in plaintext exactly once.
   * Gate this behind an admin check at the HTTP layer.
   */
  readonly registerClient: (
    input: RegisterOidcClientInput,
    registrarUserId?: string,
  ) => Effect.Effect<RegisteredOidcClient, OidcProviderError | AuthError, OidcClientStoreTag>;

  /** Look up a client (trusted config clients first, then the store). */
  readonly getClient: (
    clientId: string,
  ) => Effect.Effect<OidcClient | null, AuthError, OidcClientStoreTag>;

  /** List registered clients (store-backed only). */
  readonly listClients: () => Effect.Effect<
    ReadonlyArray<OidcClient>,
    AuthError,
    OidcClientStoreTag
  >;

  /** Update a registered client. Trusted config clients cannot be updated. */
  readonly updateClient: (
    clientId: string,
    input: UpdateOidcClientInput,
  ) => Effect.Effect<OidcClient, OidcProviderError | AuthError, OidcClientStoreTag>;

  /** Delete a registered client. */
  readonly deleteClient: (
    clientId: string,
  ) => Effect.Effect<void, OidcProviderError | AuthError, OidcClientStoreTag>;

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
    OidcClientStoreTag | OidcCodeStoreTag | OidcConsentStoreTag
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
    OidcCodeStoreTag | OidcConsentStoreTag
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
    | OidcClientStoreTag
    | OidcCodeStoreTag
    | OidcTokenStoreTag
    | UserStoreTag
    | JwtServiceTag
    | JwtKeyStoreTag
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
    OidcTokenStoreTag | UserStoreTag
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
```

## OidcProviderServiceLayer

**Signature**

```ts
export declare const OidcProviderServiceLayer: (
  config: OidcProviderConfig,
) => Layer.Layer<OidcProviderServiceTag, never, never>;
```

## OidcProviderServiceTag (class)

**Signature**

```ts
export declare class OidcProviderServiceTag
```

## OidcToken (interface)

An issued opaque token, keyed by the sha256 hex digest of its value.

**Signature**

```ts
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
```

## OidcTokenError (class)

Token endpoint failure carrying an RFC 6749 error code
(`invalid_request`, `invalid_client`, `invalid_grant`,
`unsupported_grant_type`, `invalid_scope`, `server_error`).

**Signature**

```ts
export declare class OidcTokenError
```

## OidcTokenRequest (interface)

A parsed `POST /oauth2/token` request (snake_case per RFC 6749).

**Signature**

```ts
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
```

## OidcTokenResult (interface)

A successful token response (camelCase; the HTTP layer encodes snake_case).

**Signature**

```ts
export interface OidcTokenResult {
  readonly accessToken: string;
  readonly tokenType: "Bearer";
  /** Seconds until the access token expires. */
  readonly expiresIn: number;
  readonly refreshToken?: string;
  readonly idToken?: string;
  readonly scope: string;
}
```

## OidcTokenStore

**Signature**

```ts
export declare const OidcTokenStore: typeof OidcTokenStoreTag;
```

## OidcTokenStore (interface)

Store for issued access and refresh tokens.

**Signature**

```ts
export interface OidcTokenStore {
  readonly create: (token: OidcToken) => Effect.Effect<OidcToken, AuthError>;
  readonly get: (tokenHash: string) => Effect.Effect<OidcToken | null, AuthError>;
  readonly delete: (tokenHash: string) => Effect.Effect<void, AuthError>;
}
```

## OidcTokenStoreTag (class)

**Signature**

```ts
export declare class OidcTokenStoreTag
```

## RegisterOidcClientInput (interface)

Input to {@link OidcProviderService.registerClient}.

**Signature**

```ts
export interface RegisterOidcClientInput {
  readonly name: string;
  readonly redirectUris: readonly string[];
  /** Default `"web"` (confidential — a secret is generated). */
  readonly type?: "web" | "native";
  /** Default `false`. */
  readonly skipConsent?: boolean;
  readonly metadata?: Record<string, unknown>;
}
```

## RegisteredOidcClient (interface)

Result of registering a client: the plaintext secret is shown exactly once.

**Signature**

```ts
export interface RegisteredOidcClient {
  readonly client: OidcClient;
  /** Only present for `web` (confidential) clients. */
  readonly clientSecret?: string;
}
```

## TrustedOidcClient (interface)

A statically configured, implicitly trusted client (consent skipped).

**Signature**

```ts
export interface TrustedOidcClient {
  readonly clientId: string;
  /** Plaintext secret (hashed at service creation); omit for public clients. */
  readonly clientSecret?: string;
  readonly name: string;
  readonly redirectUris: readonly string[];
  readonly type?: "web" | "native";
  readonly skipConsent?: boolean;
}
```

## UpdateOidcClientInput (interface)

Fields updatable via {@link OidcProviderService.updateClient}.

**Signature**

```ts
export interface UpdateOidcClientInput {
  readonly name?: string;
  readonly redirectUris?: readonly string[];
  readonly skipConsent?: boolean;
  readonly disabled?: boolean;
  readonly metadata?: Record<string, unknown>;
}
```

## hashOidcSecret

sha256 hex digest used for every OIDC secret at rest (tokens, codes, secrets).

**Signature**

```ts
export declare const hashOidcSecret: (value: string) => string;
```

## makeOidcProviderService

**Signature**

```ts
export declare const makeOidcProviderService: (
  config: OidcProviderConfig,
) => Effect.Effect<OidcProviderService, never>;
```
