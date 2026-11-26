# @thomasfosterau/effect-auth

An experimental Auth library for Effect: sessions, passwords, multi-factor, passkeys, OAuth, SSO, organizations, API keys, JWT and a policy-based authorization kernel, as Effect services and layers.

The headless core is the whole library as far as a consumer is concerned; the HTTP API (`/http`), the typed browser client (`/client`), SQL storage (`/sql`) and SAML (`/saml`) are subpaths you opt into, and the framework bindings and the adapters that bring a dependency of their own are the other `@thomasfosterau/effect-auth-*` packages. The core's only required peer is `effect`; the root barrel loads none of the subpaths. It runs on Node.js 22 or later and on Cloudflare Workers (`nodejs_compat`, compatibility date 2023-01-01 or later); `/saml` is Node-only.

> [!WARNING]
> Experimental, pre-1.0 and not audited. The API will change.

## Install

```bash
pnpm add @thomasfosterau/effect-auth effect
```

`effect` is a peer dependency (`^4.1.0`). Two subpaths take an optional peer: `/http` (and `/client/testing` through it) needs `@thomasfosterau/effect-jsonapi`, and `/saml` needs `@node-saml/node-saml`. Storage comes from your own store implementations, the [`/sql` subpath](https://github.com/thomasfosterau/effect-auth/blob/trunk/docs/guides/storage.md#sql-storage-sql) or an adapter package (`@thomasfosterau/effect-auth-drizzle`).

## Usage

```typescript
import { Effect, Layer } from "effect";
import * as Auth from "@thomasfosterau/effect-auth";
import * as Testing from "@thomasfosterau/effect-auth/testing";

// In-memory stores to start with; use `/sql`, an adapter or your own stores in production.
const AuthLive = Auth.SessionService.layer({
  sessionExpiresIn: { activePeriod: 30 * 86_400_000, idlePeriod: 14 * 86_400_000 },
}).pipe(Layer.provideMerge(Layer.merge(Testing.memoryStores, Auth.Hooks.Default)));

const program = Effect.gen(function* () {
  const ada = Testing.fixtureUser({ name: "Ada" });
  yield* (yield* Auth.UserServiceStore).update(ada);

  const sessions = yield* Auth.SessionService;
  // `token` goes in the cookie; the store only ever sees its digest, `session.id`.
  const { token } = yield* sessions.createSession(ada.id);
  const { user } = yield* sessions.validateSession(token);
  return user.id;
});

console.log(await Effect.runPromise(program.pipe(Effect.provide(AuthLive))));
```

The [getting-started guide](https://github.com/thomasfosterau/effect-auth/blob/trunk/docs/guides/getting-started.md) builds the same service over stores of your own and covers the runtimes and the root secret.

## Entry points

| Entry                                        | Root namespace     | Contents                                                                                                                                                                                |
| -------------------------------------------- | ------------------ | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `@thomasfosterau/effect-auth`                | `Auth`             | Sessions, users, identifiers, hooks, errors, the authorization kernel, organizations, admin, API keys, JWT, SSO, …                                                                      |
| `@thomasfosterau/effect-auth/email`          | `Auth.Email`       | Email and password sign-in, email verification, email OTP                                                                                                                               |
| `@thomasfosterau/effect-auth/password`       | `Auth.Password`    | `PasswordHasher` (PBKDF2), password reset, `HaveIBeenPwnedPlugin`                                                                                                                       |
| `@thomasfosterau/effect-auth/multifactor`    | `Auth.MultiFactor` | TOTP and backup codes, the OTP second factor, WebAuthn, and the OTP primitives                                                                                                          |
| `@thomasfosterau/effect-auth/oauth`          | `Auth.OAuth`       | `OAuthService`, provider presets, `provider` for custom ones, `generateState`, `generatePKCE`                                                                                           |
| `@thomasfosterau/effect-auth/plugins`        | `Auth.Plugins`     | First-party hooks plugins: account lockout, audit, captcha, IP rate limit, last login method, email normalization                                                                       |
| `@thomasfosterau/effect-auth/http`           | — (subpath only)   | The HTTP contract, the mountable handler (`make`, `makeAsync`), the typed Effect client, `AuthMiddleware`, the authorization middleware, `RemoteSession` (auth as a separate service)   |
| `@thomasfosterau/effect-auth/client`         | — (subpath only)   | The browser client over the HTTP contract ([guide](https://github.com/thomasfosterau/effect-auth/blob/trunk/docs/guides/client-reference.md))                                           |
| `@thomasfosterau/effect-auth/client/atoms`   | — (subpath only)   | The client session as `effect/reactivity` Atoms ([guide](https://github.com/thomasfosterau/effect-auth/blob/trunk/docs/guides/client-reference.md#the-session-atoms-clientatoms))       |
| `@thomasfosterau/effect-auth/client/testing` | — (subpath only)   | An in-process server fixture and cookie-jar `fetch` for client tests                                                                                                                    |
| `@thomasfosterau/effect-auth/sql`            | — (subpath only)   | Every store contract it covers over `effect/sql`'s `SqlClient`, plus the DDL ([guide](https://github.com/thomasfosterau/effect-auth/blob/trunk/docs/guides/storage.md#sql-storage-sql)) |
| `@thomasfosterau/effect-auth/saml`           | — (subpath only)   | The `SamlVerifier` over `@node-saml/node-saml`; Node-only ([guide](https://github.com/thomasfosterau/effect-auth/blob/trunk/docs/guides/saml.md))                                       |
| `@thomasfosterau/effect-auth/scrypt`         | — (subpath only)   | `scryptHasher` and its layer, to verify and rehash scrypt hashes; Node-only                                                                                                             |
| `@thomasfosterau/effect-auth/ladder`         | —                  | An ordered role ladder for browser UX gates; imports only `effect/Option`                                                                                                               |
| `@thomasfosterau/effect-auth/testing`        | —                  | Test helpers: run as a fixture principal, fixture users, guard assertions, store conformance suites                                                                                     |

## Guides

- [Getting started](https://github.com/thomasfosterau/effect-auth/blob/trunk/docs/guides/getting-started.md): runtimes, a first service, the root secret, what the root exports.
- [Authorization](https://github.com/thomasfosterau/effect-auth/blob/trunk/docs/guides/authorization.md): RBAC, system principals, owned and reference material.
- [Sign-in methods](https://github.com/thomasfosterau/effect-auth/blob/trunk/docs/guides/sign-in-methods.md): passwords, multi-factor, passkeys, OAuth, Cloudflare Access, email verification, delivery.
- [Rate limiting and abuse protection](https://github.com/thomasfosterau/effect-auth/blob/trunk/docs/guides/abuse-protection.md).
- [The HTTP API](https://github.com/thomasfosterau/effect-auth/blob/trunk/docs/guides/http-api.md): the handler, sign-up attributes, the endpoint reference, `RemoteSession`.
- [Storage](https://github.com/thomasfosterau/effect-auth/blob/trunk/docs/guides/storage.md): `KeyValueStore` stores, deleting a user, SQL storage.
- [The browser client](https://github.com/thomasfosterau/effect-auth/blob/trunk/docs/guides/client.md) and its [reference](https://github.com/thomasfosterau/effect-auth/blob/trunk/docs/guides/client-reference.md).
- [SAML](https://github.com/thomasfosterau/effect-auth/blob/trunk/docs/guides/saml.md), [testing an app](https://github.com/thomasfosterau/effect-auth/blob/trunk/docs/guides/testing.md), [bring your own store](https://github.com/thomasfosterau/effect-auth/blob/trunk/docs/guides/byo-stores.md), [MCP provider](https://github.com/thomasfosterau/effect-auth/blob/trunk/docs/guides/mcp-provider.md), [SCIM](https://github.com/thomasfosterau/effect-auth/blob/trunk/docs/guides/scim.md), [auth as a separate service](https://github.com/thomasfosterau/effect-auth/blob/trunk/docs/guides/split-auth-service.md), [rate limits and sessions on Durable Objects](https://github.com/thomasfosterau/effect-auth/blob/trunk/docs/guides/workers-durable-objects.md), [migrating from Better Auth](https://github.com/thomasfosterau/effect-auth/blob/trunk/docs/guides/better-auth-migration.md).

## Further reading

- [The three-library boundary](https://github.com/thomasfosterau/effect-auth/blob/trunk/docs/BOUNDARY.md): how this library relates to effect-jsonapi and legation.
- [Architecture](https://github.com/thomasfosterau/effect-auth/blob/trunk/docs/ARCHITECTURE.md), including the security model; [design decisions](https://github.com/thomasfosterau/effect-auth/blob/trunk/docs/DESIGN.md) and [ADRs](https://github.com/thomasfosterau/effect-auth/blob/trunk/docs/adr/README.md).
- [Observability](https://github.com/thomasfosterau/effect-auth/blob/trunk/docs/OBSERVABILITY.md): spans and metrics.

## License

MIT
