---
"@thomasfosterau/effect-auth": minor
---

The API layout: directory structure, package exports, service classes and naming conventions.
Highlights:

- The package is published as `@thomasfosterau/effect-auth` (the bare `effect-auth` npm name
  belongs to an unrelated package), and the client as `@thomasfosterau/effect-auth-client`.
- Feature modules live in lowercase cluster directories (`email/`, `http/`, `oauth/`,
  `password/`, `plugins/`, `multifactor/`), and the package publishes
  per-cluster subpath exports (`@thomasfosterau/effect-auth/email`, `.../http`, ...) alongside
  the root export. Authorization and session management are deliberately _not_ clusters: their
  modules (`Policy.ts`, `Entity.ts`, `Authorizer.ts`, `Protected.ts`, `Rbac.ts`,
  `SessionService.ts`, `SessionStore.ts`, `UserStore.ts`, `TrustedDevice.ts`, …) sit flat in
  `src/` and are reached from the root (`Auth.Policy.permit`, `Auth.Rbac.layer`,
  `Auth.SessionService`), with no `./authz` or `./session` subpath.
- Service tag strings and exported type names match their class names exactly, and every
  acronym follows Effect's Pascal-case convention — `ApiKeyService`, `OidcProviderService`,
  `JwtService`, `ScimService`, `SsoService`, `SamlVerifier`, `EmailOtpStore`,
  `OtpSecondFactorService`, `SmsSender`, and the `Auth.Http` cluster namespace. Only
  SCREAMING_SNAKE constants (`DEFAULT_OIDC_SCOPES`, `SCIM_USER_SCHEMA`) and protocol wire
  values (HTTP paths, operationIds, `SAMLResponse` form fields, `type: "oidc" | "saml"`)
  keep their all-caps spelling.
- There are no `*Shape` interfaces; an implementation's type is `typeof FooService.Service`.
- Services resolve their store and session/hook dependencies once at Layer construction, so
  method signatures carry `R = never` and dependencies are wired into the service layer rather
  than threaded through each call.
- Most services use Effect's `Crypto` service rather than `node:crypto`; a layer built from a
  raw `make` needs `Crypto.Crypto` (or a test double) in context.
- Constructors are module-scoped `make` / `layer` exports.
