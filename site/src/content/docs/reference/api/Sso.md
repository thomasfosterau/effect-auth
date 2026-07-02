---
title: "Sso"
description: "API reference for the Sso module."
---

## Sso overview

Enterprise SSO (single sign-on) — OIDC relying party with domain routing.

Lets tenants bring their own identity provider: register a per-organization
OIDC connection, route sign-ins by email domain, and provision users (and,
optionally, organization members) on first login. An SSO connection is, under
the hood, a dynamically-registered OAuth provider, so this module reuses the
OAuth machinery in {@link module:oauth} — {@link makeOAuthProvider},
{@link discoverOAuthEndpoints}, and the shared {@link OAuthStateStoreTag}.

SAML is out of scope for now; the store shape carries a `protocol` field so a
SAML connection type can be added later without a migration.

---

<h2 class="text-delta">Table of contents</h2>

- [utils](#utils)
  - [RegisterProviderInput (interface)](#registerproviderinput-interface)
  - [SsoConfig (interface)](#ssoconfig-interface)
  - [SsoError (class)](#ssoerror-class)
  - [SsoProvider (interface)](#ssoprovider-interface)
  - [SsoProviderStore](#ssoproviderstore)
  - [SsoProviderStore (interface)](#ssoproviderstore-interface)
  - [SsoProviderStoreTag (class)](#ssoproviderstoretag-class)
  - [SsoService](#ssoservice)
  - [SsoService (interface)](#ssoservice-interface)
  - [SsoServiceLayer](#ssoservicelayer)
  - [SsoServiceTag (class)](#ssoservicetag-class)
  - [SsoSignInResult (interface)](#ssosigninresult-interface)
  - [SsoSignInSelector (interface)](#ssosigninselector-interface)
  - [makeSsoService](#makessoservice)

---

# utils

## RegisterProviderInput (interface)

Input to {@link SsoService.registerProvider}.

**Signature**

```ts
export interface RegisterProviderInput {
  readonly issuer: string;
  readonly domain: string;
  readonly clientId: string;
  readonly clientSecret: string;
  readonly redirectUri: string;
  /** Discover `authorization`/`token`/`userinfo`/`jwks` endpoints from the issuer. */
  readonly discover?: boolean;
  readonly authorizationEndpoint?: string;
  readonly tokenEndpoint?: string;
  readonly userInfoEndpoint?: string;
  readonly jwksEndpoint?: string;
  readonly scopes?: readonly string[];
  readonly usePKCE?: boolean;
  readonly organizationId?: string;
}
```

## SsoConfig (interface)

Configuration for {@link makeSsoService}.

**Signature**

```ts
export interface SsoConfig {
  /** Default scopes when a connection doesn't specify any. */
  readonly defaultScopes?: readonly string[];
  /** Role granted when auto-adding a user to a connection's organization. */
  readonly defaultRole?: string;
}
```

## SsoError (class)

Failure to register, resolve, or complete an SSO sign-in.

**Signature**

```ts
export declare class SsoError
```

## SsoProvider (interface)

A registered SSO connection. Endpoints may be supplied directly or populated
from the issuer's discovery document at registration time.

**Signature**

```ts
export interface SsoProvider {
  readonly id: string;
  /** OIDC issuer identifier (`iss`). */
  readonly issuer: string;
  /** Email domain that routes to this provider (normalized, lowercase). */
  readonly domain: string;
  readonly protocol: "oidc";
  readonly clientId: string;
  readonly clientSecret: string;
  /** Where the IdP redirects after authorization (this app's callback URL). */
  readonly redirectUri: string;
  readonly authorizationEndpoint: string;
  readonly tokenEndpoint: string;
  readonly userInfoEndpoint?: string;
  readonly jwksEndpoint?: string;
  readonly scopes: readonly string[];
  readonly usePKCE: boolean;
  /** Organization to add the user to on first login (with {@link defaultRole}). */
  readonly organizationId?: string;
  /** User id of the admin who registered the connection. */
  readonly userId: string;
  /** Epoch milliseconds. */
  readonly createdAt: number;
}
```

## SsoProviderStore

**Signature**

```ts
export declare const SsoProviderStore: typeof SsoProviderStoreTag;
```

## SsoProviderStore (interface)

Persistent registry of SSO connections.

**Signature**

```ts
export interface SsoProviderStore {
  readonly create: (provider: SsoProvider) => Effect.Effect<SsoProvider, AuthError>;
  readonly getById: (id: string) => Effect.Effect<SsoProvider | null, AuthError>;
  readonly getByDomain: (domain: string) => Effect.Effect<SsoProvider | null, AuthError>;
  readonly list: () => Effect.Effect<ReadonlyArray<SsoProvider>, AuthError>;
}
```

## SsoProviderStoreTag (class)

**Signature**

```ts
export declare class SsoProviderStoreTag
```

## SsoService

**Signature**

```ts
export declare const SsoService: typeof SsoServiceTag;
```

## SsoService (interface)

**Signature**

```ts
export interface SsoService {
  /**
   * Register (or discover + register) an SSO connection. The registrar
   * (`registrarUserId`) is recorded on the connection; gate this behind an
   * admin check at the HTTP layer.
   */
  readonly registerProvider: (
    registrarUserId: string,
    input: RegisterProviderInput,
  ) => Effect.Effect<SsoProvider, SsoError | AuthError, SsoProviderStoreTag>;

  /**
   * Resolve the connection an email address routes to, by domain. Returns
   * `null` when no connection matches.
   */
  readonly resolveProviderForEmail: (
    email: string,
  ) => Effect.Effect<SsoProvider | null, AuthError, SsoProviderStoreTag>;

  /**
   * Begin an SSO sign-in: resolve the connection (by `providerId`, `domain`, or
   * the domain of `email`) and return the IdP authorization URL to redirect to.
   */
  readonly signIn: (
    selector: SsoSignInSelector,
  ) => Effect.Effect<
    { readonly url: string; readonly state: string },
    SsoError | AuthError,
    SsoProviderStoreTag | OAuthStateStoreTag
  >;

  /**
   * Complete the SSO callback: exchange the code, verify the profile,
   * find-or-create the user by verified email, optionally add them to the
   * connection's organization, and issue a session.
   */
  readonly handleCallback: (
    state: string,
    code: string,
  ) => Effect.Effect<
    SsoSignInResult,
    SsoError | AuthError | HookError,
    SsoProviderStoreTag | OAuthStateStoreTag | OAuthUserStoreTag | SessionManagerTag | Hooks
  >;
}
```

## SsoServiceLayer

**Signature**

```ts
export declare const SsoServiceLayer: (
  config?: SsoConfig,
) => Layer.Layer<SsoServiceTag, never, never>;
```

## SsoServiceTag (class)

**Signature**

```ts
export declare class SsoServiceTag
```

## SsoSignInResult (interface)

Result of a completed SSO sign-in.

**Signature**

```ts
export interface SsoSignInResult {
  readonly user: Types.User;
  readonly session: Types.Session;
  readonly isNewUser: boolean;
  readonly provider: SsoProvider;
}
```

## SsoSignInSelector (interface)

Where to start an SSO sign-in from.

**Signature**

```ts
export interface SsoSignInSelector {
  readonly email?: string;
  readonly providerId?: string;
  readonly domain?: string;
}
```

## makeSsoService

**Signature**

```ts
export declare const makeSsoService: (config?: SsoConfig) => Effect.Effect<SsoService, never>;
```
