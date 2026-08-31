---
"@thomasfosterau/effect-auth": minor
---

BREAKING: API restructure — directory layout, package exports, service classes, and naming
conventions. Pre-1.0, so this ships as a minor per semver's 0.x carve-out; there is no compat
layer, so every consumer needs to update call sites. See `docs/migration.md` for the full
before/after mapping. Highlights:

- The package is published as `@thomasfosterau/effect-auth` (the bare `effect-auth` npm name
  belongs to an unrelated package), and the client as `@thomasfosterau/effect-auth-client`.
- Feature modules moved into lowercase cluster directories (`email/`, `http/`, `oauth/`,
  `password/`, `plugins/`, `multifactor/`), and the package now publishes
  per-cluster subpath exports (`@thomasfosterau/effect-auth/email`, `.../http`, ...) alongside
  the root export. Authorization and session management are deliberately _not_ clusters: their
  modules (`Policy.ts`, `Entity.ts`, `Authorizer.ts`, `Protected.ts`, `RBAC.ts`,
  `SessionService.ts`, `SessionStore.ts`, `UserStore.ts`, `TrustedDevice.ts`, …) sit flat in
  `src/` and are reached from the root (`Auth.Policy.permit`, `Auth.RoleStore`,
  `Auth.SessionService`), with no `./authz` or `./session` subpath.
- Service tag strings and exported type names now match their class names exactly, with
  acronyms following Effect's Pascal-case convention (`JwtService` → `JWTService`,
  `EmailOtpStore` → `EmailOTPStore`, etc.) except where the acronym opens a multi-word name
  that reads as a word — `ApiKeyService`, `OidcProviderService`.
- `*Shape` interfaces (~65 across the codebase) are deleted; use `typeof FooService.Service`
  instead.
- Services now resolve their store and session/hook dependencies once at Layer construction
  instead of per method call, so method signatures carry `R = never` and dependencies are wired
  into the service layer rather than threaded through each call.
- Most services adopt Effect's `Crypto` service instead of `node:crypto`; layers that previously
  needed no extra wiring may now require `Crypto.layer` (or a test double) in context.
- Every `makeFooService`-style constructor is renamed to a module-scoped `make`/`layer` export.
