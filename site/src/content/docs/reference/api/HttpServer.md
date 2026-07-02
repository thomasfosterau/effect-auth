---
title: "HttpServer"
description: "API reference for the HttpServer module."
---

## HttpServer overview

---

<h2 class="text-delta">Table of contents</h2>

- [utils](#utils)
  - [AuthServices (type alias)](#authservices-type-alias)
  - [AuthWebHandlerOptions (interface)](#authwebhandleroptions-interface)
  - [CookieConfig (interface)](#cookieconfig-interface)
  - [MultiSessionConfig (interface)](#multisessionconfig-interface)
  - [authGroupLayer](#authgrouplayer)
  - [makeAuthWebHandler](#makeauthwebhandler)

---

# utils

## AuthServices (type alias)

The services the auth handlers require. Your `services` layer must provide
all of these (a superset is fine). They are the existing core services plus
the stores the orchestration services depend on, plus the `Hooks` service
(provide `Hooks.Default` for no-op hooks, or a `composePlugins([...])` stack).

**Signature**

```ts
export type AuthServices =
  | AuthLifecycleServiceTag
  | SessionManagerTag
  | EmailPasswordStoreTag
  | PasswordHasherTag
  | EmailVerificationServiceTag
  | EmailVerificationStoreTag
  | PasswordResetServiceTag
  | PasswordResetStoreTag
  | PasswordResetUserStoreTag
  | UserServiceTag
  | UserServiceStoreTag
  | Hooks;
```

## AuthWebHandlerOptions (interface)

**Signature**

```ts
export interface AuthWebHandlerOptions {
  /** Your service layer (SessionManager, AuthLifecycle, stores, ...). */
  readonly services: Layer.Layer<AuthServices>;
  /** Cookie configuration. */
  readonly cookie?: CookieConfig;
  /**
   * Enable multi-session: one browser can hold several signed-in accounts and
   * switch between them. Each sign-in appends to a device session list; the
   * active session is the primary cookie. See the `/multi-session/*` endpoints.
   */
  readonly multiSession?: MultiSessionConfig;
  /**
   * Mount path prefix to strip before routing, e.g. `"/api/auth"`. When set, a
   * request to `/api/auth/sign-in` is routed to the `/sign-in` endpoint.
   */
  readonly prefix?: string;
  /**
   * Origins (e.g. `"https://app.example.com"`) allowed to make state-changing
   * (non-GET/HEAD/OPTIONS) requests, in addition to the request's own origin.
   *
   * Browsers attach an `Origin` header to cross-origin (and most same-origin)
   * mutating requests; when the header is present and matches neither the
   * request URL's origin nor this list, the request is rejected with `403`
   * before it reaches a handler (CSRF protection). Requests without an
   * `Origin` header (curl, server-to-server) are allowed through.
   */
  readonly trustedOrigins?: ReadonlyArray<string>;
  /**
   * Serve the generated OpenAPI document and an API reference UI. When `true`,
   * `GET {prefix}/openapi.json` returns the OpenAPI 3.1 document and
   * `GET {prefix}/reference` returns a Scalar reference page. Default `false`
   * (keep off in production unless you intend to expose the docs publicly).
   */
  readonly docs?: boolean;
}
```

## CookieConfig (interface)

Server implementation for the auth HTTP contract.

`makeAuthWebHandler` turns the contract + your service layer into a standard
Web `Request => Response` handler that any framework can mount. Handlers call
the existing Effect services; the session cookie and session resolution are
handled here so framework integrations no longer hand-roll them.

**Signature**

```ts
export interface CookieConfig {
  /** Cookie name. Default `conduit_session`. */
  readonly name?: string;
  /** Mark the cookie `Secure`. Default `true` (set `false` for local http). */
  readonly secure?: boolean;
  /** Cookie path. Default `/`. */
  readonly path?: string;
  /**
   * Signed session-data cookie cache. When enabled, a short-lived HMAC-signed
   * copy of the session + user is stored in a `${name}_data` cookie so
   * authenticated requests can be served without a session-store read (up to
   * `maxAge`). See {@link SessionCacheConfig}.
   */
  readonly cache?: SessionCacheConfig;
  /**
   * Record the sign-in method in a NON-httpOnly `${name}_last_method` cookie
   * whenever a sign-in endpoint issues a session, so login pages can
   * highlight the user's previous method (`"email-password"`,
   * `"magic-link"`, `"sso"`, ...). Pass `true` for a 30-day cookie or an
   * object to tune the lifetime. Pair with `makeLastLoginMethodPlugin` to
   * also record the method into `session.attributes.method` server-side.
   */
  readonly lastLoginMethod?: boolean | { readonly maxAge?: number };
}
```

## MultiSessionConfig (interface)

Multiple concurrent accounts per client (device-scoped session list).

**Signature**

```ts
export interface MultiSessionConfig {
  /** Maximum concurrent sessions retained per device. Default 5. */
  readonly maximumSessions?: number;
}
```

## authGroupLayer

Layer implementing the `auth` group handlers.

**Signature**

```ts
export declare const authGroupLayer: (
  config?: CookieConfig,
  multiSession?: MultiSessionConfig,
) => Layer.Layer<
  ApiGroup<"AuthApi", "auth">,
  never,
  | HttpRouter.Request<"Requires", SessionManagerTag>
  | HttpRouter.Request<"Requires", Hooks>
  | HttpRouter.Request<"Requires", PasswordHasherTag>
  | HttpRouter.Request<"Requires", AuthLifecycleServiceTag>
  | HttpRouter.Request<"Requires", EmailPasswordStoreTag>
  | HttpRouter.Request<"Requires", EmailVerificationServiceTag>
  | HttpRouter.Request<"Requires", EmailVerificationStoreTag>
  | HttpRouter.Request<"Requires", UserServiceTag>
  | HttpRouter.Request<"Requires", UserServiceStoreTag>
  | HttpRouter.Request<"Requires", PasswordResetServiceTag>
  | HttpRouter.Request<"Requires", PasswordResetStoreTag>
  | HttpRouter.Request<"Requires", PasswordResetUserStoreTag>
>;
```

## makeAuthWebHandler

Build a standard Web `Request => Response` handler for the auth API.

Mount the returned `handler` in any framework (SvelteKit/Next/Hono/...).
`dispose` releases the handler's scope.

**Signature**

```ts
export declare const makeAuthWebHandler: (options: AuthWebHandlerOptions) => {
  readonly handler: (request: Request, context?: Context.Context<never>) => Promise<Response>;
  readonly dispose: () => Promise<void>;
};
```
