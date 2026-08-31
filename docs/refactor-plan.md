# API Structure Refactor Plan

Agreed direction for the effect-auth core package restructure (July 2026).
This document is the source of truth for the ordered refactor issues; each
issue links back here.

## Principles

- **Big, maintainable core** with `effect` as its only runtime dependency
  (superseding the original allowance for native/pure-JS auth primitives:
  Argon2id moved to `packages/argon2` and the WebAuthn parsers were
  reimplemented in-repo). ORMs and storage drivers (e.g. `drizzle-orm`) live in
  adapter packages, never in core.
- **Idiomatic Effect v4** as defined by the effect-solutions guides
  (`bunx effect-solutions show services-and-layers`), falling back to
  Effect-core conventions where the guides are silent.
- **Clean break**: no compat re-export barrels, no deprecated aliases.
  Ships as a breaking release with a migration table (old name/path → new).

## 1. Directory layout — "clear clusters only", lowercase dirs

Directories are lowercase (Effect ecosystem convention: `effect/unstable/http`).
Files are PascalCase with all-caps acronyms. Anything not listed stays flat
in `src/`.

| Directory   | Contents                                                                                                                                                                 |
| ----------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| `email/`    | EmailAddress, EmailOTP (was EmailOtp), EmailOTPService, EmailPassword, EmailVerification + tests                                                                         |
| `http/`     | Http, HTTPApi, HTTPApiSchemas, HTTPClient, HTTPServer, HTTPMiddleware (from src root), OpenApi.test + tests                                                              |
| `oauth/`    | as today (OAuth, index)                                                                                                                                                  |
| `session/`  | SessionService, SessionStore, UserStore, MultiSession, TrustedDevice + tests. `Session.ts` compat barrel is **deleted** (clean break)                                    |
| `password/` | Password, PasswordReset, PasswordTraits, Argon2, HaveIBeenPwned                                                                                                          |
| `plugins/`  | AccountLockout, Audit, Captcha, IPRateLimit, LastLoginMethod, NormalizeEmail, RateLimit plugin, AbusePlugins.test (drop the `Plugin` file-name suffix inside `plugins/`) |
| `authz/`    | Authorization, Permission, RBAC                                                                                                                                          |

## 2. Naming

- **Acronyms all-caps** in exported identifiers AND file names:
  `EmailOTP.ts`, `JWT.ts`, `OIDCProvider.ts`, `SSO.ts`, `APIKey.ts`,
  `RBAC.ts`, `HTTPServer.ts`, `IPRateLimit`, `ClientIP`. Directories stay
  lowercase.
- **Service classes keep the `-Service` suffix** (`SessionService`,
  `MultiFactorService`, `EmailOTPService`) to avoid collisions with same-domain
  record types (`Types.Session` etc.). Store tags keep the `Store` suffix.
- **Tag strings match final class names**: `"@effect-auth/EmailOTPService"`.

## 3. Service definition pattern

Class-style `Context.Service` per the effect-solutions guide (verified
first-class in Effect v4 — `Context.ts` `@since 4.0.0`, `ServiceClass`):

```ts
export class MultiFactorService extends Context.Service<
  MultiFactorService,
  {
    readonly enable: (
      userId: string,
      password: string,
    ) => Effect.Effect<MultiFactorEnableResult, MultiFactorError | Errors.AuthError>;
    // ...
  }
>()("@effect-auth/MultiFactorService") {
  static readonly layer = (config: MultiFactorConfig) =>
    Layer.effect(MultiFactorService, make(config));
}
```

- Separate exported `*Shape` interfaces are **deleted**. Consumers and
  adapters use `typeof FooStore.Service` when they need the shape type.
- Store contracts get identical treatment (they are `Context.Service` tags).
- Applies to every service in core (~30 tags).

## 4. Requirement leakage: methods have `R = never`

Full adoption of the guide's rule. Stores/hooks/session dependencies are
yielded **once at Layer construction**; method signatures carry only the
error channel:

```ts
export const make = (config: EmailPasswordConfig) =>
  Effect.gen(function* () {
    const store = yield* EmailPasswordStore;
    const sessions = yield* SessionService;
    const hooks = yield* Hooks;
    return {
      signIn: Effect.fn("EmailPasswordService.signIn")((email, password) =>
        /* Effect<AuthResult, AuthError> — R = never */
      ),
    };
  });
```

This removes every `leakingRequirements` diagnostic and changes all
`make*`/`layer` signatures — consumers wire store layers into the service
layer instead of providing stores per call.

## 5. Effect `Crypto` service

Use `effect`'s `Crypto` service wherever its API suffices (`randomBytes`,
`randomInt*`, `digest`, UUIDs) — yielded at Layer creation per §4. Its
`randomBytes` returns `Effect<Uint8Array, PlatformError>`; map/absorb
`PlatformError` at the layer boundary rather than widening public error
channels.

Remaining `node:crypto` usage is corralled into exactly three leaf modules,
ready to swap as `Crypto` grows:

| Module                 | Why it stays on node:crypto |
| ---------------------- | --------------------------- |
| `password/Password.ts` | scrypt                      |
| `TokenHash.ts`         | `timingSafeEqual`           |
| `Cipher.ts`            | AES-256-GCM, HMAC           |

## 6. Public API surface

`package.json` `exports` subpaths per cluster, plus a curated root that also
re-exports namespaces:

```
"effect-auth"          → core spine (Errors, Types, Hooks, session services,
                         plugin infrastructure, utils) + namespace re-exports
                         (export * as Email, * as HTTP, * as OAuth, ...)
"effect-auth/email"    → email/ cluster
"effect-auth/http"     → http/ cluster
"effect-auth/oauth"    → oauth/ cluster
"effect-auth/password" → password/ cluster
"effect-auth/authz"    → authz/ cluster
"effect-auth/plugins"  → plugins/ cluster
```

Flat feature modules (JWT, Organization, MagicLink, ...) remain exported
from the root until/unless they earn a cluster.

## 7. Conventions sweep

- `.ts` import extensions everywhere (tests currently mix `.js`).
- Module-scoped `make`/`layer` exports (drop `makeFooService` names);
  namespace imports disambiguate: `EmailPassword.make(config)`.
- `Effect.fn("Service.method")` tracing wrappers on service methods
  (lands with §4).

## Issue slicing (ordered; each lands green before the next)

Green = `vp check`, `tsc --noEmit`, `vp test --typecheck --run`, and
`packages/client` still compiles.

1. **Restructure** — directories, file moves/renames, acronym caps (§1, §2 file names). Mechanical, big.
2. **Public API** — exports map, per-cluster barrels, curated root (§6).
3. **Service merge** — class-style tags, delete `*Shape` interfaces, tag-string renames (§3, part of §2).
4. **`R = never`** — resolve deps at Layer creation; `Effect.fn` tracing (§4, depends on 3).
5. **Crypto adoption** — Effect `Crypto` service + node:crypto corral (§5, depends on 4).
6. **Conventions sweep** — import extensions, `make`/`layer` naming, leftovers (§7).

## Module consolidations (part of issue 1)

- `email/EmailOtp.ts` + `email/EmailOTPService.ts` → one `email/EmailOTP.ts`.
  The HTTPServer-wired implementation (currently `EmailOtp.ts`) is the
  survivor; fold in anything unique from `EmailOTPService.ts` (diff
  feature-by-feature first), then delete it. Final class name
  `EmailOTPService`.
- `WebAuthnService.ts` merges into `WebAuthn.ts` — one module per feature.

## Deferred

- Second-factor cluster (`TwoFactor`, `OtpSecondFactor`, `MultiFactorService`,
  `WebAuthn`, `Otp`) — revisit after the core clusters land.
