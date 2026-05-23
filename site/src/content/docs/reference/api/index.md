---
title: "index"
description: "API reference for the index module."
---

## index overview

Effect Auth - Authentication and Authorization library for Effect

A generic authentication and authorization library following guidelines from
Lucia, Copenhagen, and Oslo projects. Uses Effect's Request/Resolver pattern
for flexible, composable authentication flows.

---

<h2 class="text-delta">Table of contents</h2>

- [exports](#exports)
  - [From "./AuthLifecycle.js"](#from-authlifecyclejs)
  - [From "./Authorization.js"](#from-authorizationjs)
  - [From "./EmailPassword.js"](#from-emailpasswordjs)
  - [From "./EmailVerification.js"](#from-emailverificationjs)
  - [From "./Errors.js"](#from-errorsjs)
  - [From "./OAuth.js"](#from-oauthjs)
  - [From "./Otp.js"](#from-otpjs)
  - [From "./Password.js"](#from-passwordjs)
  - [From "./PasswordReset.js"](#from-passwordresetjs)
  - [From "./RateLimit.js"](#from-ratelimitjs)
  - [From "./Requests.js"](#from-requestsjs)
  - [From "./Resolvers.js"](#from-resolversjs)
  - [From "./Session.js"](#from-sessionjs)
  - [From "./Types.js"](#from-typesjs)
  - [From "./User.js"](#from-userjs)
  - [From "./WebAuthn.js"](#from-webauthnjs)
- [utils](#utils)
  - [Context](#context)
  - [Effect](#effect)
  - [Layer](#layer)
  - [RequestResolver](#requestresolver)

---

# exports

## From "./AuthLifecycle.js"

High-level auth lifecycle orchestration.

**Signature**

```ts
export * from "./AuthLifecycle.js";
```

## From "./Authorization.js"

Authorization primitives.

**Signature**

```ts
export * from "./Authorization.js";
```

## From "./EmailPassword.js"

Email and password authentication flows.

**Signature**

```ts
export * from "./EmailPassword.js";
```

## From "./EmailVerification.js"

Email verification (inspired by BetterAuth).

**Signature**

```ts
export * from "./EmailVerification.js";
```

## From "./Errors.js"

Tagged errors raised across the library.

**Signature**

```ts
export * from "./Errors.js";
```

## From "./OAuth.js"

OAuth 2.0 / OIDC (inspired by BetterAuth).

**Signature**

```ts
export * from "./OAuth.js";
```

## From "./Otp.js"

OTP utilities (TOTP and HOTP, following Oslo patterns).

**Signature**

```ts
export * from "./Otp.js";
```

## From "./Password.js"

Password hashing (following Oslo patterns).

**Signature**

```ts
export * from "./Password.js";
```

## From "./PasswordReset.js"

Password reset flows.

**Signature**

```ts
export * from "./PasswordReset.js";
```

## From "./RateLimit.js"

Rate limiting (inspired by BetterAuth).

**Signature**

```ts
export * from "./RateLimit.js";
```

## From "./Requests.js"

Effect `Request` definitions for auth operations.

**Signature**

```ts
export * from "./Requests.js";
```

## From "./Resolvers.js"

Request resolvers wiring stores to requests.

**Signature**

```ts
export * from "./Resolvers.js";
```

## From "./Session.js"

Session management (following Lucia/Copenhagen guidelines).

**Signature**

```ts
export * from "./Session.js";
```

## From "./Types.js"

Effect Auth - Authentication and Authorization library for Effect

A generic authentication and authorization library following guidelines from
Lucia, Copenhagen, and Oslo projects. Uses Effect's Request/Resolver pattern
for flexible, composable authentication flows.

**Signature**

```ts
export * from "./Types.js";
```

## From "./User.js"

User service primitive.

**Signature**

```ts
export * from "./User.js";
```

## From "./WebAuthn.js"

WebAuthn (passkey authentication).

**Signature**

```ts
export * from "./WebAuthn.js";
```

# utils

## Context

Re-export of `Context` from `effect`.

**Signature**

```ts
export declare const Context: typeof import("/home/user/effect-auth/node_modules/effect/dist/dts/Context");
```

## Effect

Re-export of `Effect` from `effect`.

**Signature**

```ts
export declare const Effect: typeof import("/home/user/effect-auth/node_modules/effect/dist/dts/Effect");
```

## Layer

Re-export of `Layer` from `effect`.

**Signature**

```ts
export declare const Layer: typeof import("/home/user/effect-auth/node_modules/effect/dist/dts/Layer");
```

## RequestResolver

Re-export of `RequestResolver` from `effect`.

**Signature**

```ts
export declare const RequestResolver: typeof import("/home/user/effect-auth/node_modules/effect/dist/dts/RequestResolver");
```
