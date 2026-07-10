# Migration guide: API restructure (0.1.0 → next)

This is a breaking release. It covers every public rename and move made across the six-issue API
restructure milestone (`docs/refactor-plan.md`): directory layout, the `package.json` exports map,
service-class consolidation, `R = never` signatures, `Crypto` service adoption, and the final
conventions sweep. There is no compat layer — update call sites to the new names/paths directly.

## 1. Directory layout and import paths

Feature modules moved into lowercase cluster directories. Update relative imports (internal) or
subpath imports (external) accordingly.

| Old path                                                           | New path                                             |
| ------------------------------------------------------------------ | ---------------------------------------------------- |
| `src/EmailAddress.ts`                                              | `src/email/EmailAddress.ts`                          |
| `src/EmailOtp.ts` + `src/EmailOTPService.ts`                       | `src/email/EmailOTP.ts` (merged)                     |
| `src/EmailPassword.ts`                                             | `src/email/EmailPassword.ts`                         |
| `src/EmailVerification.ts`                                         | `src/email/EmailVerification.ts`                     |
| `src/Http.ts`                                                      | `src/http/Http.ts`                                   |
| `src/HttpApi.ts`                                                   | `src/http/HTTPApi.ts`                                |
| `src/HttpApiSchemas.ts`                                            | `src/http/HTTPApiSchemas.ts`                         |
| `src/HttpClient.ts`                                                | `src/http/HTTPClient.ts`                             |
| `src/HttpMiddleware.ts`                                            | `src/http/HTTPMiddleware.ts`                         |
| `src/HttpServer.ts`                                                | `src/http/HTTPServer.ts`                             |
| `src/OAuth/OAuth.ts`, `OAuth/Scope.ts`                             | `src/oauth/OAuth.ts`, `oauth/Scope.ts`               |
| `src/SessionService.ts`                                            | `src/session/SessionService.ts`                      |
| `src/SessionStore.ts`                                              | `src/session/SessionStore.ts`                        |
| `src/UserStore.ts`                                                 | `src/session/UserStore.ts`                           |
| `src/TrustedDevice.ts`                                             | `src/session/TrustedDevice.ts`                       |
| `src/Session.ts` (compat barrel)                                   | **deleted** — import `SessionService` directly       |
| `src/Password.ts`                                                  | `src/password/Password.ts`                           |
| `src/PasswordReset.ts`                                             | `src/password/PasswordReset.ts`                      |
| `src/HaveIBeenPwned.ts`                                            | `src/password/HaveIBeenPwned.ts`                     |
| `src/Argon2.ts`                                                    | `src/password/Argon2.ts`                             |
| `src/Permission.ts`                                                | `src/authz/Permission.ts`                            |
| `src/Authorization.ts`                                             | `src/authz/Authorization.ts`                         |
| `src/Rbac.ts`                                                      | `src/authz/RBAC.ts`                                  |
| `src/AuditPlugin.ts`                                               | `src/plugins/Audit.ts`                               |
| `src/NormalizeEmailPlugin.ts`                                      | `src/plugins/NormalizeEmail.ts`                      |
| `src/RateLimitPlugin.ts`                                           | `src/plugins/RateLimit.ts`                           |
| `src/AccountLockoutPlugin.ts`                                      | `src/plugins/AccountLockout.ts`                      |
| `src/CaptchaPlugin.ts`                                             | `src/plugins/Captcha.ts`                             |
| `src/LastLoginMethodPlugin.ts`                                     | `src/plugins/LastLoginMethod.ts`                     |
| `src/IpRateLimitPlugin.ts`                                         | `src/plugins/IPRateLimit.ts`                         |
| `src/WebAuthnService.ts`                                           | merged into `src/WebAuthn.ts`                        |
| `src/MultiFactorService.ts` (orphaned duplicate of `TwoFactor.ts`) | **deleted**                                          |
| `src/TwoFactor.ts`                                                 | `src/secondfactor/MultiFactor.ts` (renamed — see §8) |
| `src/OTPSecondFactor.ts`                                           | `src/secondfactor/OTPSecondFactor.ts`                |
| `src/WebAuthn.ts`                                                  | `src/secondfactor/WebAuthn.ts`                       |
| `src/OTP.ts`                                                       | `src/secondfactor/OTP.ts`                            |

Flat feature modules that only got acronym-case fixes (still exported from the package root, not
clustered):

| Old file             | New file             |
| -------------------- | -------------------- |
| `ApiKey.ts`          | `APIKey.ts`          |
| `ClientIp.ts`        | `ClientIP.ts`        |
| `Jwt.ts`             | `JWT.ts`             |
| `OidcProvider.ts`    | `OIDCProvider.ts`    |
| `OtpSecondFactor.ts` | `OTPSecondFactor.ts` |
| `PhoneOtp.ts`        | `PhoneOTP.ts`        |
| `Sso.ts`             | `SSO.ts`             |
| `Otp.ts`             | `OTP.ts`             |

## 2. Package exports

Before the restructure, `effect-auth` had a single root export. It now publishes per-cluster
subpaths, with the `types` condition listed first (TypeScript's own guidance for conditional
exports):

```jsonc
{
  "exports": {
    ".": { "types": "./dist/index.d.ts", "import": "./dist/index.js" },
    "./email": { "types": "./dist/email/index.d.ts", "import": "./dist/email/index.js" },
    "./http": { "types": "./dist/http/index.d.ts", "import": "./dist/http/index.js" },
    "./oauth": { "types": "./dist/oauth/index.d.ts", "import": "./dist/oauth/index.js" },
    "./session": { "types": "./dist/session/index.d.ts", "import": "./dist/session/index.js" },
    "./password": { "types": "./dist/password/index.d.ts", "import": "./dist/password/index.js" },
    "./plugins": { "types": "./dist/plugins/index.d.ts", "import": "./dist/plugins/index.js" },
    "./authz": { "types": "./dist/authz/index.d.ts", "import": "./dist/authz/index.js" },
    "./secondfactor": {
      "types": "./dist/secondfactor/index.d.ts",
      "import": "./dist/secondfactor/index.js",
    },
  },
}
```

The root package (`effect-auth`) still re-exports every cluster as a namespace (`Email`, `HTTP`,
`OAuth`, `Session`-flavored exports, `Password`, `Plugins`, `Authz`, `SecondFactor`) alongside the
flat, non-clustered feature modules (JWT, Admin, Organization, …) — no import changes needed there
beyond the renames below.

## 3. Tag-string and identifier acronym fixes

Service tag strings (the `"@effect-auth/…"` string passed to `Context.Service`) and exported type
names now match their class names exactly, with acronyms fully capitalized:

| Old                                                                                                                | New                                                                                                 |
| ------------------------------------------------------------------------------------------------------------------ | --------------------------------------------------------------------------------------------------- |
| `"@effect-auth/ApiKeyService"` / `ApiKeyStore`                                                                     | `APIKeyService` / `APIKeyStore`                                                                     |
| `"@effect-auth/ClientIp"`                                                                                          | `ClientIP`                                                                                          |
| `"@effect-auth/EmailOtpService"` / `EmailOtpStore` / `EmailOtpUserStore`                                           | `EmailOTPService` / `EmailOTPStore` / `EmailOTPUserStore`                                           |
| `"@effect-auth/JwtService"` / `JwtKeyStore`                                                                        | `JWTService` / `JWTKeyStore`                                                                        |
| `"@effect-auth/OidcClientStore"` / `OidcCodeStore` / `OidcConsentStore` / `OidcTokenStore` / `OidcProviderService` | `OIDCClientStore` / `OIDCCodeStore` / `OIDCConsentStore` / `OIDCTokenStore` / `OIDCProviderService` |
| `"@effect-auth/OtpSecondFactorService"` / `OtpSecondFactorStore`                                                   | `OTPSecondFactorService` / `OTPSecondFactorStore`                                                   |
| `"@effect-auth/PhoneOtpService"` / `PhoneOtpStore` / `PhoneOtpUserStore`                                           | `PhoneOTPService` / `PhoneOTPStore` / `PhoneOTPUserStore`                                           |
| `"@effect-auth/SsoService"` / `SsoProviderStore`                                                                   | `SSOService` / `SSOProviderStore`                                                                   |
| `"@effect-auth/http/AuthMiddleware"`                                                                               | `"@effect-auth/AuthMiddleware"`                                                                     |
| `"@effect-auth/http/OptionalAuthMiddleware"`                                                                       | `"@effect-auth/OptionalAuthMiddleware"`                                                             |
| `IpResolvableRequest`                                                                                              | `IPResolvableRequest`                                                                               |
| `AuthorizationUrlResult`                                                                                           | `AuthorizationURLResult`                                                                            |
| `SSOUrlView`                                                                                                       | `SSOURLView`                                                                                        |
| `HttpIPRateLimitConfig`                                                                                            | `HTTPIPRateLimitConfig`                                                                             |

## 4. Service classes: `*Shape` interfaces deleted

Every standalone `FooServiceShape`/`FooStoreShape` interface (~65 across the codebase, e.g.
`SessionServiceShape`, `EmailPasswordServiceShape`, `OAuthServiceShape`, `PasswordHasherShape`,
`WebAuthnServiceShape`, `MessagesShape`, …) has been deleted. Service and store contracts are now
plain `Context.Service` classes; consumers who need the shape type reference
`typeof FooService.Service` instead:

```ts
// before
import type { EmailPasswordServiceShape } from "effect-auth";
const impl: EmailPasswordServiceShape = { ... };

// after
import { EmailPasswordService } from "effect-auth";
const impl: typeof EmailPasswordService.Service = { ... };
```

The `SessionManager` / `makeSessionManager` compat aliases (and `SessionManagerShape`) for the old
`SessionService` name are also gone — use `SessionService` / `SessionService.layer(...)` directly.

## 5. `R = never` service construction

Every service's `make`/`layer` now resolves its store and session/hook dependencies **once at
Layer construction** instead of per method call. Method signatures on the returned service object
carry only the error channel (`R = never`); callers no longer provide stores per call — wire the
store layer into the service layer instead:

```ts
// before: dependency threaded through every call
service.signIn(email, password).pipe(Effect.provideService(EmailPasswordStore, store));

// after: dependency resolved once, at layer construction
const layer = EmailPasswordService.layer(config).pipe(Layer.provide(storeLayer));
```

## 6. `Crypto` service adoption

Most services now use Effect's `Crypto` service (`randomBytes`, `randomInt*`, `digest`, UUIDs)
instead of `node:crypto`, yielded once at layer construction like other dependencies. Layers that
previously worked with no extra wiring may now require `Crypto.layer` (or a test double) in
context. Direct `node:crypto` usage is now corralled into exactly three modules:
`password/Password.ts` (scrypt), `TokenHash.ts` (`timingSafeEqual`), and `Cipher.ts` (AES-256-GCM,
HMAC, JWS/DER asymmetric primitives).

The `hashOtp` deprecated alias for `hashToken` (previously left over in the email-OTP module) is
gone — call `hashToken` directly.

## 7. Constructor naming: `makeFooService` → module-scoped `make`/`layer`

Every relative import now uses the `.ts` extension (`rewriteRelativeImportExtensions` rewrites it
to `.js` at emit time), and every `makeFooService`-style constructor has been renamed to a
module-scoped export. Import the module as a namespace to disambiguate:

```ts
// before
import { makeEmailPasswordService } from "effect-auth/email";
const service = yield * makeEmailPasswordService(config);

// after
import * as EmailPassword from "effect-auth/email"; // or the specific file internally
const service = yield * EmailPassword.make(config);
```

| Old export                        | Module                            | New export                    |
| --------------------------------- | --------------------------------- | ----------------------------- |
| `makeAccountManagementService`    | `AccountManagement.ts`            | `make`                        |
| `makeAdminService`                | `Admin.ts`                        | `make`                        |
| `makeAes256GcmCipher`             | `Cipher.ts`                       | `aes256GcmCipher`             |
| `makeAnonymousService`            | `Anonymous.ts`                    | `make`                        |
| `makeAPIKeyService`               | `APIKey.ts`                       | `make`                        |
| `makeArgon2Hasher`                | `password/Argon2.ts`              | `argon2Hasher`                |
| `Argon2HasherLayer`               | `password/Argon2.ts`              | `argon2HasherLayer`           |
| `makeAuthClient`                  | `http/HTTPClient.ts`              | `client`                      |
| `makeAuthLifecycleService`        | `AuthLifecycle.ts`                | `make`                        |
| `makeAuthMiddlewareLayer`         | `http/HTTPMiddleware.ts`          | `layer`                       |
| `makeOptionalAuthMiddlewareLayer` | `http/HTTPMiddleware.ts`          | `optionalLayer`               |
| `makeAuthWebHandler`              | `http/HTTPServer.ts`              | `make`                        |
| `makeClientIPLayer`               | `ClientIP.ts`                     | `clientIPLayer`               |
| `makeDeviceAuthorizationService`  | `DeviceAuthorization.ts`          | `make`                        |
| `makeEmailOTPService`             | `email/EmailOTP.ts`               | `make`                        |
| `makeEmailPasswordService`        | `email/EmailPassword.ts`          | `make`                        |
| `makeEmailVerificationService`    | `email/EmailVerification.ts`      | `make`                        |
| `makeGoogleOneTapService`         | `GoogleOneTap.ts`                 | `make`                        |
| `makeInMemoryRoleStore`           | `authz/RBAC.ts`                   | `make`                        |
| `makeJWTService`                  | `JWT.ts`                          | `make`                        |
| `makeRemoteJwksVerifier`          | `JWT.ts`                          | `remoteJwksVerifier`          |
| `makeLastLoginMethodPlugin`       | `plugins/LastLoginMethod.ts`      | `make`                        |
| `makeMagicLinkService`            | `MagicLink.ts`                    | `make`                        |
| `makeOAuthProvider`               | `oauth/OAuth.ts`                  | `provider`                    |
| `makeOAuthService`                | `oauth/OAuth.ts`                  | `make`                        |
| `makeAppleClientSecret`           | `oauth/OAuth.ts`                  | `appleClientSecret`           |
| `makeOIDCProviderService`         | `OIDCProvider.ts`                 | `make`                        |
| `makeOrganizationService`         | `Organization.ts`                 | `make`                        |
| `makeOTPSecondFactorService`      | `secondfactor/OTPSecondFactor.ts` | `make`                        |
| `makePasswordResetService`        | `password/PasswordReset.ts`       | `make`                        |
| `makePermission`                  | `authz/Permission.ts`             | `make`                        |
| `makePhoneOTPService`             | `PhoneOTP.ts`                     | `make`                        |
| `makeRateLimiter`                 | `RateLimit.ts`                    | `make`                        |
| `makeRateLimiterPersistence`      | `RateLimitPersistence.ts`         | `rateLimiterPersistence`      |
| `RateLimiterPersistenceLayer`     | `RateLimitPersistence.ts`         | `rateLimiterPersistenceLayer` |
| `makeRoleBasedPolicy`             | `authz/Authorization.ts`          | `make`                        |
| `makeSSOService`                  | `SSO.ts`                          | `make`                        |
| `makeTrustedDeviceService`        | `session/TrustedDevice.ts`        | `make`                        |
| `makeTrustedDeviceGateShape`      | `session/TrustedDevice.ts`        | `gate`                        |
| `makeTwoFactorService`            | `secondfactor/MultiFactor.ts`     | `make`                        |
| `makeUserService`                 | `User.ts`                         | `make`                        |
| `makeUsernameService`             | `Username.ts`                     | `make`                        |
| `makeWebAuthnService`             | `secondfactor/WebAuthn.ts`        | `make`                        |
| `makeOAuthStateStoreKV`           | `KeyValueStores.ts`               | `oauthStateStoreKV`           |
| `makeChallengeStoreKV`            | `KeyValueStores.ts`               | `challengeStoreKV`            |
| `makeRateLimitStoreKV`            | `KeyValueStores.ts`               | `rateLimitStoreKV`            |
| `makeEmailVerificationStoreKV`    | `KeyValueStores.ts`               | `emailVerificationStoreKV`    |
| `makePasswordResetStoreKV`        | `KeyValueStores.ts`               | `passwordResetStoreKV`        |
| `makeMagicLinkStoreKV`            | `KeyValueStores.ts`               | `magicLinkStoreKV`            |
| `makeEmailOTPStoreKV`             | `KeyValueStores.ts`               | `emailOTPStoreKV`             |
| `makePendingTwoFactorStoreKV`     | `KeyValueStores.ts`               | `pendingMultiFactorStoreKV`   |
| `makeIdentifierStoreKV`           | `KeyValueStores.ts`               | `identifierStoreKV`           |
| `makeGoogleOneTapNonceStoreKV`    | `KeyValueStores.ts`               | `googleOneTapNonceStoreKV`    |
| `makeMultiAlgorithmVerifier`      | `password/Password.ts`            | `multiAlgorithmVerifier`      |
| `makePBKDF2Hasher`                | `password/Password.ts`            | `pbkdf2Hasher`                |
| `makeScryptHasher`                | `password/Password.ts`            | `scryptHasher`                |

`makePlugin` (the generic plugin-Layer factory in `Hooks.ts`, shared across every plugin module —
not a per-service constructor) is unchanged.

## 8. Second-factor cluster: `TwoFactor` → `MultiFactor` rename

The TOTP/backup-code module (moved into `src/secondfactor/` above) is renamed from `TwoFactor` to
`MultiFactor` throughout — the class, its tag string, every exported identifier, the HTTP routes
and wire schema types, the client SDK namespace, and the observability metrics. This reuses the
`MultiFactorService` name freed up by the orphaned-duplicate deletion in §1 — it is not related to
that deleted file.

| Old                                                                                                                                                                                  | New                                                                                                                                                                                |
| ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `src/TwoFactor.ts`                                                                                                                                                                   | `src/secondfactor/MultiFactor.ts`                                                                                                                                                  |
| `"@effect-auth/TwoFactorService"`                                                                                                                                                    | `"@effect-auth/MultiFactorService"`                                                                                                                                                |
| `TwoFactorService`                                                                                                                                                                   | `MultiFactorService`                                                                                                                                                               |
| `TwoFactorError`                                                                                                                                                                     | `MultiFactorError`                                                                                                                                                                 |
| `TwoFactorRecord`                                                                                                                                                                    | `MultiFactorRecord`                                                                                                                                                                |
| `TwoFactorStore`                                                                                                                                                                     | `MultiFactorStore`                                                                                                                                                                 |
| `PendingTwoFactor` / `PendingTwoFactorStore`                                                                                                                                         | `PendingMultiFactor` / `PendingMultiFactorStore`                                                                                                                                   |
| `TwoFactorConfig`                                                                                                                                                                    | `MultiFactorConfig`                                                                                                                                                                |
| `TwoFactorEnableResult`                                                                                                                                                              | `MultiFactorEnableResult`                                                                                                                                                          |
| `TwoFactorChallenge`                                                                                                                                                                 | `MultiFactorChallenge`                                                                                                                                                             |
| `TwoFactorVerifyResult` / `TwoFactorVerifyOptions`                                                                                                                                   | `MultiFactorVerifyResult` / `MultiFactorVerifyOptions`                                                                                                                             |
| `twoFactorConfig`                                                                                                                                                                    | `multiFactorConfig`                                                                                                                                                                |
| `TwoFactorGateLayer`                                                                                                                                                                 | `MultiFactorGateLayer`                                                                                                                                                             |
| `TrustedDeviceWithTwoFactorGateLayer`                                                                                                                                                | `TrustedDeviceWithMultiFactorGateLayer`                                                                                                                                            |
| `Auth.SecondFactor.TwoFactorService` (and every other `TwoFactor*` export)                                                                                                           | `Auth.SecondFactor.MultiFactorService` (and every renamed export above)                                                                                                            |
| `client.twoFactor.*` (client SDK)                                                                                                                                                    | `client.multiFactor.*`                                                                                                                                                             |
| `TwoFactorEnableView`, `TwoFactorPasswordPayload`, `TwoFactorConfirmPayload`, `TwoFactorVerifyPayload` (wire schemas)                                                                | `MultiFactorEnableView`, `MultiFactorPasswordPayload`, `MultiFactorConfirmPayload`, `MultiFactorVerifyPayload`                                                                     |
| `/two-factor/enable`, `/two-factor/confirm`, `/two-factor/disable`, `/two-factor/verify-totp`, `/two-factor/verify-backup-code`, `/two-factor/regenerate-backup-codes` (HTTP routes) | `/multi-factor/enable`, `/multi-factor/confirm`, `/multi-factor/disable`, `/multi-factor/verify-totp`, `/multi-factor/verify-backup-code`, `/multi-factor/regenerate-backup-codes` |
| `twoFactorEnable`, `twoFactorConfirm`, `twoFactorDisable`, `twoFactorRegenerateBackupCodes`, `twoFactorVerifyTotp`, `twoFactorVerifyBackupCode` (HTTP API operationIds)              | `multiFactorEnable`, `multiFactorConfirm`, `multiFactorDisable`, `multiFactorRegenerateBackupCodes`, `multiFactorVerifyTotp`, `multiFactorVerifyBackupCode`                        |
| `"two-factor"` (the `lastLoginMethod`/session-attribute value recorded on a successful redeem)                                                                                       | `"multi-factor"`                                                                                                                                                                   |
| `effect-auth.two_factor_challenges.total`, `effect-auth.two_factor_verifications.total` (metrics)                                                                                    | `effect-auth.multi_factor_challenges.total`, `effect-auth.multi_factor_verifications.total`                                                                                        |
| `recordTwoFactorChallenge`, `recordTwoFactorVerification`                                                                                                                            | `recordMultiFactorChallenge`, `recordMultiFactorVerification`                                                                                                                      |

`SecondFactorGate`/`SecondFactorChallenge` (the generic gate abstraction in `email/EmailPassword.ts`,
shared with `OTPSecondFactor`) and the `secondfactor/` directory name itself are **not** part of
this rename — only the TOTP-specific module and its symbols changed.

## Validation

- `vp check`, `bunx tsc --noEmit`, `vp test --typecheck --run` — all green
- `packages/client` typechecks against the new API
- `grep -rn 'from "\./.*\.js"' src/ packages/` — no matches
- `grep -rnE "export const make[A-Z]" src/` — no matches
