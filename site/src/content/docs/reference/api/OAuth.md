---
title: "OAuth"
description: "API reference for the OAuth module."
---

## OAuth overview

OAuth 2.0 and OpenID Connect types for effect-auth

Provides type definitions for OAuth2 flows, provider configurations,
and related data structures.

---

<h2 class="text-delta">Table of contents</h2>

- [utils](#utils)
  - [AppleProvider](#appleprovider)
  - [AuthorizationUrlResult (interface)](#authorizationurlresult-interface)
  - [DiscordProvider](#discordprovider)
  - [DiscoveredEndpoints (interface)](#discoveredendpoints-interface)
  - [DropboxProvider](#dropboxprovider)
  - [FacebookProvider](#facebookprovider)
  - [GitHubProvider](#githubprovider)
  - [GitLabProvider](#gitlabprovider)
  - [GoogleProvider](#googleprovider)
  - [HuggingFaceProvider](#huggingfaceprovider)
  - [KickProvider](#kickprovider)
  - [LinkedInProvider](#linkedinprovider)
  - [MicrosoftProvider](#microsoftprovider)
  - [NotionProvider](#notionprovider)
  - [OAuthAccount (interface)](#oauthaccount-interface)
  - [OAuthAccountStore (class)](#oauthaccountstore-class)
  - [OAuthAccountStoreShape (interface)](#oauthaccountstoreshape-interface)
  - [OAuthCallbackResult (interface)](#oauthcallbackresult-interface)
  - [OAuthClientConfig (interface)](#oauthclientconfig-interface)
  - [OAuthCreateUserInput (interface)](#oauthcreateuserinput-interface)
  - [OAuthProvider (interface)](#oauthprovider-interface)
  - [OAuthProviderConfig (interface)](#oauthproviderconfig-interface)
  - [OAuthService (class)](#oauthservice-class)
  - [OAuthServiceOptions (interface)](#oauthserviceoptions-interface)
  - [OAuthServiceShape (interface)](#oauthserviceshape-interface)
  - [OAuthSignInResult (interface)](#oauthsigninresult-interface)
  - [OAuthState (interface)](#oauthstate-interface)
  - [OAuthStateStore (class)](#oauthstatestore-class)
  - [OAuthStateStoreShape (interface)](#oauthstatestoreshape-interface)
  - [OAuthTokenResponse (interface)](#oauthtokenresponse-interface)
  - [OAuthUserInfo (interface)](#oauthuserinfo-interface)
  - [OAuthUserStore (class)](#oauthuserstore-class)
  - [OAuthUserStoreShape (interface)](#oauthuserstoreshape-interface)
  - [ProfileMap](#profilemap)
  - [RedditProvider](#redditprovider)
  - [RobloxProvider](#robloxprovider)
  - [SlackProvider](#slackprovider)
  - [SpotifyProvider](#spotifyprovider)
  - [TikTokProvider](#tiktokprovider)
  - [TwitchProvider](#twitchprovider)
  - [TwitterProvider](#twitterprovider)
  - [ZoomProvider](#zoomprovider)
  - [discoverOAuthEndpoints](#discoveroauthendpoints)
  - [generateNonce](#generatenonce)
  - [generatePKCE](#generatepkce)
  - [generateState](#generatestate)
  - [makeAppleClientSecret](#makeappleclientsecret)
  - [makeOAuthProvider](#makeoauthprovider)
  - [makeOAuthService](#makeoauthservice)
  - [nested](#nested)
  - [profile](#profile)
  - [str](#str)
  - [verifyIdToken](#verifyidtoken)

---

# utils

## AppleProvider

Sign-in with Apple. Apple returns identity only via the OIDC `id_token`
(`response_mode=form_post`, `name`/`email` scopes). `clientSecret` must be a
signed ES256 JWT — generate it with {@link makeAppleClientSecret}.

**Signature**

```ts
export declare const AppleProvider: (config: OAuthClientConfig) => OAuthProvider;
```

## AuthorizationUrlResult (interface)

Authorization URL generation result

**Signature**

```ts
export interface AuthorizationUrlResult {
  readonly url: string;
  readonly state: string;
  readonly codeVerifier?: string;
}
```

## DiscordProvider

**Signature**

```ts
export declare const DiscordProvider: (config: {
  clientId: string;
  clientSecret: string;
  redirectUri: string;
}) => OAuthProvider;
```

## DiscoveredEndpoints (interface)

Endpoint set resolved from an OpenID Connect discovery document, in the
shape {@link OAuthProviderConfig} expects.

**Signature**

```ts
export interface DiscoveredEndpoints {
  readonly issuer: string;
  readonly authorizationEndpoint: string;
  readonly tokenEndpoint: string;
  readonly userInfoEndpoint?: string;
  readonly jwksEndpoint?: string;
}
```

## DropboxProvider

Dropbox (POST userinfo; `token_access_type=offline` for refresh tokens).

**Signature**

```ts
export declare const DropboxProvider: (config: OAuthClientConfig) => OAuthProvider;
```

## FacebookProvider

Facebook Login (Graph API userinfo; `picture` is nested under `data.url`).

**Signature**

```ts
export declare const FacebookProvider: (config: OAuthClientConfig) => OAuthProvider;
```

## GitHubProvider

**Signature**

```ts
export declare const GitHubProvider: (config: {
  clientId: string;
  clientSecret: string;
  redirectUri: string;
}) => OAuthProvider;
```

## GitLabProvider

GitLab (`gitlab.com` by default; pass `baseUrl` for self-hosted).

**Signature**

```ts
export declare const GitLabProvider: (
  config: OAuthClientConfig & { readonly baseUrl?: string },
) => OAuthProvider;
```

## GoogleProvider

Pre-built OAuth providers

**Signature**

```ts
export declare const GoogleProvider: (config: {
  clientId: string;
  clientSecret: string;
  redirectUri: string;
}) => OAuthProvider;
```

## HuggingFaceProvider

Hugging Face (OpenID Connect; PKCE).

**Signature**

```ts
export declare const HuggingFaceProvider: (config: OAuthClientConfig) => OAuthProvider;
```

## KickProvider

Kick (PKCE required; profile under `data[0]`).

**Signature**

```ts
export declare const KickProvider: (config: OAuthClientConfig) => OAuthProvider;
```

## LinkedInProvider

LinkedIn (OpenID Connect userinfo).

**Signature**

```ts
export declare const LinkedInProvider: (config: OAuthClientConfig) => OAuthProvider;
```

## MicrosoftProvider

**Signature**

```ts
export declare const MicrosoftProvider: (config: {
  clientId: string;
  clientSecret: string;
  redirectUri: string;
  tenant?: string;
}) => OAuthProvider;
```

## NotionProvider

Notion (Basic auth; profile via `/v1/users/me` bot owner).

**Signature**

```ts
export declare const NotionProvider: (config: OAuthClientConfig) => OAuthProvider;
```

## OAuthAccount (interface)

OAuth account linking to user

**Signature**

```ts
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
```

## OAuthAccountStore (class)

OAuth account store context tag

**Signature**

```ts
export declare class OAuthAccountStore
```

## OAuthAccountStoreShape (interface)

Storage interface for OAuth accounts (persistent, database)

**Signature**

```ts
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
```

## OAuthCallbackResult (interface)

OAuth callback result

**Signature**

```ts
export interface OAuthCallbackResult {
  readonly account: OAuthAccount;
  readonly isNewUser: boolean;
  readonly user?: {
    readonly id: string;
    readonly email?: string;
    readonly name?: string;
  };
}
```

## OAuthClientConfig (interface)

The `{ clientId, clientSecret, redirectUri }` triple every provider needs.

**Signature**

```ts
export interface OAuthClientConfig {
  readonly clientId: string;
  readonly clientSecret: string;
  readonly redirectUri: string;
}
```

## OAuthCreateUserInput (interface)

Input for creating a user from an OAuth provider profile.

**Signature**

```ts
export interface OAuthCreateUserInput {
  readonly email: string;
  readonly emailVerified: boolean;
  readonly name?: string;
  readonly image?: string;
}
```

## OAuthProvider (interface)

OAuth provider interface

**Signature**

```ts
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
```

## OAuthProviderConfig (interface)

OAuth2 provider configuration

**Signature**

```ts
export interface OAuthProviderConfig {
  readonly clientId: string;
  readonly clientSecret: string;
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
```

## OAuthService (class)

**Signature**

```ts
export declare class OAuthService
```

## OAuthServiceOptions (interface)

Options controlling {@link OAuthServiceShape} behaviour.

**Signature**

```ts
export interface OAuthServiceOptions {
  /**
   * When a new OAuth account arrives with a provider-verified email that
   * matches an existing user, link the account to that user instead of
   * creating a new one. Defaults to `true`. Only ever applies when the
   * provider reports `email_verified: true`.
   */
  readonly autoLinkByVerifiedEmail?: boolean;
}
```

## OAuthServiceShape (interface)

OAuth service for managing OAuth flows

**Signature**

```ts
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
    AuthError | OAuthProviderError | OAuthStateNotFoundError | OAuthStateExpiredError,
    OAuthStateStore | OAuthAccountStore
  >;

  readonly unlinkAccount: (
    userId: string,
    provider: string,
  ) => Effect.Effect<void, AuthError, OAuthAccountStore>;

  readonly refreshAccessToken: (
    userId: string,
    provider: string,
  ) => Effect.Effect<string, AuthError | OAuthProviderError, OAuthAccountStore>;
}
```

## OAuthSignInResult (interface)

Result of a complete OAuth sign-in (callback handled, user resolved or
created, account linked, session issued).

**Signature**

```ts
export interface OAuthSignInResult {
  readonly user: Types.User;
  readonly account: OAuthAccount;
  readonly session: Types.Session;
  readonly isNewUser: boolean;
  readonly returnTo?: string;
}
```

## OAuthState (interface)

OAuth2 state for CSRF protection

**Signature**

```ts
export interface OAuthState {
  readonly state: string;
  readonly provider: string;
  readonly codeVerifier?: string; // For PKCE
  readonly nonce?: string; // For OIDC id_token replay protection
  readonly returnTo?: string;
  readonly createdAt: number;
  readonly expiresAt: number;
}
```

## OAuthStateStore (class)

OAuth state store context tag

**Signature**

```ts
export declare class OAuthStateStore
```

## OAuthStateStoreShape (interface)

Storage interface for OAuth state (temporary, Redis/memory)

**Signature**

```ts
export interface OAuthStateStoreShape {
  readonly create: (state: OAuthState) => Effect.Effect<OAuthState, AuthError>;
  /** Get a pending state entry, or `null` when unknown/expired-and-purged. */
  readonly get: (state: string) => Effect.Effect<OAuthState | null, AuthError>;
  readonly delete: (state: string) => Effect.Effect<void, AuthError>;
}
```

## OAuthTokenResponse (interface)

OAuth2 token response

**Signature**

```ts
export interface OAuthTokenResponse {
  readonly access_token: string;
  readonly token_type: string;
  readonly expires_in?: number;
  readonly refresh_token?: string;
  readonly scope?: string;
  readonly id_token?: string; // For OIDC
}
```

## OAuthUserInfo (interface)

User info from OAuth provider

**Signature**

```ts
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
```

## OAuthUserStore (class)

OAuth user store context tag

**Signature**

```ts
export declare class OAuthUserStore
```

## OAuthUserStoreShape (interface)

Minimal user store the OAuth sign-in flow needs to create or look up users
from provider profiles. Implement alongside {@link OAuthAccountStoreShape}.

**Signature**

```ts
export interface OAuthUserStoreShape {
  readonly getUser: (userId: string) => Effect.Effect<Types.User, UserNotFoundError>;
  readonly getUserByEmail: (email: string) => Effect.Effect<Types.User | null, AuthError>;
  readonly createUser: (input: OAuthCreateUserInput) => Effect.Effect<Types.User, AuthError>;
}
```

## ProfileMap

Profile-mapping helpers for use in custom `mapProfile` implementations.
These are the same utilities used by every built-in provider preset
(Facebook, Twitter, Spotify, …), now exported so custom providers can be
just as terse. Each helper is also available as a top-level named export
(`str`, `nested`, `profile`).

**Signature**

```ts
export declare const ProfileMap: {
  readonly str: (v: unknown) => string | undefined;
  readonly nested: (v: unknown, ...path: string[]) => unknown;
  readonly profile: (
    base: Record<string, unknown>,
    fields: {
      readonly id: unknown;
      readonly email?: string | undefined;
      readonly name?: string | undefined;
      readonly picture?: string | undefined;
      readonly email_verified?: boolean | undefined;
    },
  ) => OAuthUserInfo;
};
```

See the [Custom OAuth providers guide](/guides/custom-oauth-provider/) for
usage examples.

## RedditProvider

Reddit (Basic auth; `identity` scope; no email; `duration=permanent`).

**Signature**

```ts
export declare const RedditProvider: (config: OAuthClientConfig) => OAuthProvider;
```

## RobloxProvider

Roblox (OpenID Connect; PKCE required).

**Signature**

```ts
export declare const RobloxProvider: (config: OAuthClientConfig) => OAuthProvider;
```

## SlackProvider

Slack (Sign in with Slack / OpenID Connect).

**Signature**

```ts
export declare const SlackProvider: (config: OAuthClientConfig) => OAuthProvider;
```

## SpotifyProvider

Spotify (Basic auth token exchange; `images[0].url`, `display_name`).

**Signature**

```ts
export declare const SpotifyProvider: (config: OAuthClientConfig) => OAuthProvider;
```

## TikTokProvider

TikTok (uses `client_key`; PKCE; profile under `data.user`).

**Signature**

```ts
export declare const TikTokProvider: (config: OAuthClientConfig) => OAuthProvider;
```

## TwitchProvider

Twitch (OpenID Connect userinfo).

**Signature**

```ts
export declare const TwitchProvider: (config: OAuthClientConfig) => OAuthProvider;
```

## TwitterProvider

X/Twitter OAuth2 (PKCE + Basic auth required; email needs elevated access).

**Signature**

```ts
export declare const TwitterProvider: (config: OAuthClientConfig) => OAuthProvider;
```

## ZoomProvider

Zoom (Basic auth; `first_name`/`last_name`, `pic_url`).

**Signature**

```ts
export declare const ZoomProvider: (config: OAuthClientConfig) => OAuthProvider;
```

## discoverOAuthEndpoints

Populate a provider's endpoints from an issuer's
`/.well-known/openid-configuration`. Spread the result into a
{@link makeOAuthProvider} config to build a generic OIDC provider.

**Signature**

```ts
export declare const discoverOAuthEndpoints: (
  issuerUrl: string,
) => Effect.Effect<DiscoveredEndpoints, OAuthProviderError>;
```

## generateNonce

Generate a cryptographically secure random nonce for OIDC id_token replay
protection.

**Signature**

```ts
export declare const generateNonce: () => Effect.Effect<string, never>;
```

## generatePKCE

Generate PKCE code verifier and challenge

**Signature**

```ts
export declare const generatePKCE: () => Effect.Effect<
  { codeVerifier: string; codeChallenge: string },
  never
>;
```

## generateState

Generate a cryptographically secure random state parameter

**Signature**

```ts
export declare const generateState: () => Effect.Effect<string, never>;
```

## makeAppleClientSecret

Build the ES256-signed client-secret JWT Apple requires (valid up to 6
months; Apple caps `exp` at 15777000s). Pass the result as `clientSecret`
to {@link AppleProvider}.

**Signature**

```ts
export declare const makeAppleClientSecret: (params: {
  readonly teamId: string;
  readonly clientId: string;
  readonly keyId: string;
  readonly privateKey: string;
  readonly expiresIn?: number;
  readonly now?: number;
}) => Effect.Effect<string, OAuthProviderError>;
```

## makeOAuthProvider

Create an OAuth provider

**Signature**

```ts
export declare const makeOAuthProvider: (
  name: string,
  config: OAuthProviderConfig,
  usePKCE?: boolean,
) => OAuthProvider;
```

## makeOAuthService

Create an OAuth service with configured providers

**Signature**

```ts
export declare const makeOAuthService: (
  providers: Record<string, OAuthProvider>,
  options?: OAuthServiceOptions,
) => Effect.Effect<OAuthServiceShape, never>;
```

## nested

Safely traverse a nested object by a chain of keys. Returns `undefined` at the
first missing or non-object step.

**Signature**

```ts
export declare const nested: (v: unknown, ...path: string[]) => unknown;
```

**Example**

```ts
nested(raw["picture"], "data", "url"); // → raw.picture?.data?.url
```

## profile

Build an `OAuthUserInfo` from a base record plus normalized identity fields,
omitting any that are `undefined` (satisfies `exactOptionalPropertyTypes`).

**Signature**

```ts
export declare const profile: (
  base: Record<string, unknown>,
  fields: {
    readonly id: unknown;
    readonly email?: string | undefined;
    readonly name?: string | undefined;
    readonly picture?: string | undefined;
    readonly email_verified?: boolean | undefined;
  },
) => OAuthUserInfo;
```

## str

Coerce a value to `string` — returns `undefined` for non-strings.

**Signature**

```ts
export declare const str: (v: unknown) => string | undefined;
```

## verifyIdToken

Verify and decode an OIDC `id_token` (compact JWS) against a provider's
JWKS. Validates the signature (RS256, ES256, or EdDSA), then `iss`, `aud`,
`exp`, and — when supplied — `nonce`. Returns the decoded claims.

**Signature**

```ts
export declare const verifyIdToken: (
  idToken: string,
  params: {
    readonly provider: string;
    readonly jwksEndpoint: string;
    readonly issuer?: string;
    readonly audience?: string;
    readonly nonce?: string;
    readonly now?: number;
  },
) => Effect.Effect<Record<string, unknown>, OAuthProviderError>;
```
