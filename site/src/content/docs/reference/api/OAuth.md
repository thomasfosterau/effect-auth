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
  - [AuthorizationUrlResult (interface)](#authorizationurlresult-interface)
  - [DiscordProvider](#discordprovider)
  - [GitHubProvider](#githubprovider)
  - [GoogleProvider](#googleprovider)
  - [MicrosoftProvider](#microsoftprovider)
  - [OAuthAccount (interface)](#oauthaccount-interface)
  - [OAuthAccountStore](#oauthaccountstore)
  - [OAuthAccountStore (interface)](#oauthaccountstore-interface)
  - [OAuthAccountStoreTag (class)](#oauthaccountstoretag-class)
  - [OAuthCallbackResult (interface)](#oauthcallbackresult-interface)
  - [OAuthProvider (interface)](#oauthprovider-interface)
  - [OAuthProviderConfig (interface)](#oauthproviderconfig-interface)
  - [OAuthService](#oauthservice)
  - [OAuthService (interface)](#oauthservice-interface)
  - [OAuthServiceLayer](#oauthservicelayer)
  - [OAuthServiceTag (class)](#oauthservicetag-class)
  - [OAuthState (interface)](#oauthstate-interface)
  - [OAuthStateStore](#oauthstatestore)
  - [OAuthStateStore (interface)](#oauthstatestore-interface)
  - [OAuthStateStoreTag (class)](#oauthstatestoretag-class)
  - [OAuthTokenResponse (interface)](#oauthtokenresponse-interface)
  - [OAuthUserInfo (interface)](#oauthuserinfo-interface)
  - [generatePKCE](#generatepkce)
  - [generateState](#generatestate)
  - [makeOAuthProvider](#makeoauthprovider)
  - [makeOAuthService](#makeoauthservice)

---

# utils

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

## GitHubProvider

**Signature**

```ts
export declare const GitHubProvider: (config: {
  clientId: string;
  clientSecret: string;
  redirectUri: string;
}) => OAuthProvider;
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

## OAuthAccountStore

**Signature**

```ts
export declare const OAuthAccountStore: typeof OAuthAccountStoreTag;
```

## OAuthAccountStore (interface)

Storage interface for OAuth accounts (persistent, database)

**Signature**

```ts
export interface OAuthAccountStore {
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

## OAuthAccountStoreTag (class)

OAuth account store context tag

**Signature**

```ts
export declare class OAuthAccountStoreTag
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

## OAuthProvider (interface)

OAuth provider interface

**Signature**

```ts
export interface OAuthProvider {
  readonly name: string;
  readonly config: OAuthProviderConfig;
  readonly generateAuthorizationUrl: (
    scopes?: readonly string[],
  ) => Effect.Effect<AuthorizationUrlResult, OAuthProviderError | AuthError, OAuthStateStoreTag>;
  readonly exchangeCode: (
    code: string,
    codeVerifier?: string,
  ) => Effect.Effect<OAuthTokenResponse, OAuthProviderError>;
  readonly getUserInfo: (accessToken: string) => Effect.Effect<OAuthUserInfo, OAuthProviderError>;
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
}
```

## OAuthService

**Signature**

```ts
export declare const OAuthService: typeof OAuthServiceTag;
```

## OAuthService (interface)

OAuth service for managing OAuth flows

**Signature**

```ts
export interface OAuthService {
  readonly generateAuthorizationUrl: (
    provider: string,
    options?: { scopes?: readonly string[]; returnTo?: string },
  ) => Effect.Effect<AuthorizationUrlResult, AuthError | OAuthProviderError, OAuthStateStoreTag>;

  readonly handleCallback: (
    state: string,
    code: string,
    options?: { linkToUserId?: string },
  ) => Effect.Effect<
    OAuthCallbackResult,
    AuthError | OAuthProviderError | OAuthStateNotFoundError | OAuthStateExpiredError,
    OAuthStateStoreTag | OAuthAccountStoreTag
  >;

  readonly linkAccount: (
    userId: string,
    provider: string,
    code: string,
    state: string,
  ) => Effect.Effect<
    OAuthAccount,
    AuthError | OAuthProviderError | OAuthStateNotFoundError | OAuthStateExpiredError,
    OAuthStateStoreTag | OAuthAccountStoreTag
  >;

  readonly unlinkAccount: (
    userId: string,
    provider: string,
  ) => Effect.Effect<void, AuthError, OAuthAccountStoreTag>;

  readonly refreshAccessToken: (
    userId: string,
    provider: string,
  ) => Effect.Effect<string, AuthError | OAuthProviderError, OAuthAccountStoreTag>;
}
```

## OAuthServiceLayer

**Signature**

```ts
export declare const OAuthServiceLayer: (
  providers: Record<string, OAuthProvider>,
) => Layer.Layer<OAuthServiceTag, never, never>;
```

## OAuthServiceTag (class)

**Signature**

```ts
export declare class OAuthServiceTag
```

## OAuthState (interface)

OAuth2 state for CSRF protection

**Signature**

```ts
export interface OAuthState {
  readonly state: string;
  readonly provider: string;
  readonly codeVerifier?: string; // For PKCE
  readonly returnTo?: string;
  readonly createdAt: number;
  readonly expiresAt: number;
}
```

## OAuthStateStore

**Signature**

```ts
export declare const OAuthStateStore: typeof OAuthStateStoreTag;
```

## OAuthStateStore (interface)

Storage interface for OAuth state (temporary, Redis/memory)

**Signature**

```ts
export interface OAuthStateStore {
  readonly create: (state: OAuthState) => Effect.Effect<OAuthState, AuthError>;
  readonly get: (state: string) => Effect.Effect<OAuthState, AuthError>;
  readonly delete: (state: string) => Effect.Effect<void, AuthError>;
}
```

## OAuthStateStoreTag (class)

OAuth state store context tag

**Signature**

```ts
export declare class OAuthStateStoreTag
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
) => Effect.Effect<OAuthService, never>;
```
