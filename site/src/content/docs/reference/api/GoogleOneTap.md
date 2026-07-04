---
title: "GoogleOneTap"
description: "API reference for the GoogleOneTap module."
---

## GoogleOneTap overview

Google One Tap sign-in.

The browser's One Tap prompt yields a `credential` — an OIDC `id_token`
signed by Google. This module verifies it against Google's published JWKS
(signature, `iss`, `aud` = your OAuth client id, `exp`) via the shared
{@link module:oauth} `verifyIdToken`, then finds-or-creates the user by
their verified email and issues a session.

---

<h2 class="text-delta">Table of contents</h2>

- [utils](#utils)
  - [GOOGLE_ISSUERS](#google_issuers)
  - [GOOGLE_JWKS_ENDPOINT](#google_jwks_endpoint)
  - [GoogleOneTapConfig (interface)](#googleonetapconfig-interface)
  - [GoogleOneTapError (class)](#googleonetaperror-class)
  - [GoogleOneTapService (class)](#googleonetapservice-class)
  - [GoogleOneTapServiceShape (interface)](#googleonetapserviceshape-interface)
  - [GoogleOneTapSignInResult (interface)](#googleonetapsigninresult-interface)
  - [makeGoogleOneTapService](#makegoogleonetapservice)

---

# utils

## GOOGLE_ISSUERS

The two issuer values Google mints `id_token`s under.

**Signature**

```ts
export declare const GOOGLE_ISSUERS: readonly [
  "https://accounts.google.com",
  "accounts.google.com",
];
```

## GOOGLE_JWKS_ENDPOINT

Google's JWKS document location.

**Signature**

```ts
export declare const GOOGLE_JWKS_ENDPOINT: "https://www.googleapis.com/oauth2/v3/certs";
```

## GoogleOneTapConfig (interface)

Configuration for {@link makeGoogleOneTapService}.

**Signature**

```ts
export interface GoogleOneTapConfig {
  /** Your Google OAuth client id — the credential's required `aud`. */
  readonly clientId: string;
  /** Override the JWKS endpoint (tests). Default {@link GOOGLE_JWKS_ENDPOINT}. */
  readonly jwksEndpoint?: string;
  /** Override the accepted issuers (tests). Default {@link GOOGLE_ISSUERS}. */
  readonly issuers?: readonly string[];
}
```

## GoogleOneTapError (class)

Failure to verify a One Tap credential or complete the sign-in.

**Signature**

```ts
export declare class GoogleOneTapError
```

## GoogleOneTapService (class)

**Signature**

```ts
export declare class GoogleOneTapService
```

## GoogleOneTapServiceShape (interface)

**Signature**

```ts
export interface GoogleOneTapServiceShape {
  /**
   * Verify a One Tap `credential` (id_token) and sign the user in:
   * find-or-create by the token's verified email, then issue a session.
   */
  readonly signIn: (
    credential: string,
  ) => Effect.Effect<
    GoogleOneTapSignInResult,
    GoogleOneTapError | AuthError | HookError,
    OAuthUserStore | SessionManager | Hooks
  >;
}
```

## GoogleOneTapSignInResult (interface)

Result of a completed One Tap sign-in.

**Signature**

```ts
export interface GoogleOneTapSignInResult {
  readonly user: Types.User;
  readonly session: Types.Session;
  readonly isNewUser: boolean;
  /** The verified id_token claims (sub, email, name, picture, ...). */
  readonly claims: Record<string, unknown>;
}
```

## makeGoogleOneTapService

**Signature**

```ts
export declare const makeGoogleOneTapService: (
  config: GoogleOneTapConfig,
) => Effect.Effect<GoogleOneTapServiceShape, never>;
```
