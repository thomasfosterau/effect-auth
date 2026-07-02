---
title: "Http"
description: "API reference for the Http module."
---

## Http overview

HTTP protocol for effect-auth (optional; requires `effect/unstable/httpapi`).

Re-exported from the package root under the `Http` namespace, e.g.
`Auth.Http.AuthApi`, `Auth.Http.makeAuthWebHandler`, `Auth.Http.makeAuthClient`.

---

<h2 class="text-delta">Table of contents</h2>

- [exports](#exports)
  - [From "./HttpApi.js"](#from-httpapijs)
  - [From "./HttpApiSchemas.js"](#from-httpapischemasjs)
  - [From "./HttpClient.js"](#from-httpclientjs)
  - [From "./HttpServer.js"](#from-httpserverjs)
  - [From "./SessionCookieCache.js"](#from-sessioncookiecachejs)

---

# exports

## From "./HttpApi.js"

The `AuthApi` contract (groups + endpoints).

**Signature**

```ts
export * from "./HttpApi.js";
```

## From "./HttpApiSchemas.js"

HTTP protocol for effect-auth (optional; requires `effect/unstable/httpapi`).

Re-exported from the package root under the `Http` namespace, e.g.
`Auth.Http.AuthApi`, `Auth.Http.makeAuthWebHandler`, `Auth.Http.makeAuthClient`.

**Signature**

```ts
export * from "./HttpApiSchemas.js";
```

## From "./HttpClient.js"

Typed, Effect-native client.

**Signature**

```ts
export * from "./HttpClient.js";
```

## From "./HttpServer.js"

Server: handler layers and the mountable web handler.

**Signature**

```ts
export * from "./HttpServer.js";
```

## From "./SessionCookieCache.js"

Signed session-data cookie cache (config + codec).

**Signature**

```ts
export * from "./SessionCookieCache.js";
```
