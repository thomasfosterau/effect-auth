# Migration guide: API restructure (0.1.0 → next)

This is a breaking release. It covers every public rename and move made across the six-issue API
restructure milestone (`docs/refactor-plan.md`): directory layout, the `package.json` exports map,
service-class consolidation, `R = never` signatures, `Crypto` service adoption, and the final
conventions sweep. There is no compat layer — update call sites to the new names/paths directly.

## 1. Directory layout and import paths

Feature modules moved into lowercase cluster directories. Update relative imports (internal) or
subpath imports (external) accordingly.

| Old path                                                           | New path                                                     |
| ------------------------------------------------------------------ | ------------------------------------------------------------ |
| `src/EmailAddress.ts`                                              | `src/email/EmailAddress.ts`                                  |
| `src/EmailOtp.ts` + `src/EmailOTPService.ts`                       | `src/email/EmailOTP.ts` (merged)                             |
| `src/EmailPassword.ts`                                             | `src/email/EmailPassword.ts`                                 |
| `src/EmailVerification.ts`                                         | `src/email/EmailVerification.ts`                             |
| `src/Http.ts`                                                      | `src/http/Http.ts`                                           |
| `src/HttpApi.ts`                                                   | `src/http/HttpApi.ts`                                        |
| `src/HttpApiSchemas.ts`                                            | `src/http/HttpApiSchema.ts`                                  |
| `src/HttpClient.ts`                                                | `src/http/HttpClient.ts`                                     |
| `src/HttpMiddleware.ts`                                            | `src/http/HttpMiddleware.ts`                                 |
| `src/HttpServer.ts`                                                | `src/http/HttpServer.ts`                                     |
| `src/OAuth/OAuth.ts`, `OAuth/Scope.ts`                             | `src/oauth/OAuth.ts`, `oauth/Scope.ts`                       |
| `src/SessionService.ts`                                            | `src/SessionService.ts` (unchanged — briefly `src/session/`) |
| `src/SessionStore.ts`                                              | `src/SessionStore.ts` (unchanged — briefly `src/session/`)   |
| `src/UserStore.ts`                                                 | `src/UserStore.ts` (unchanged — briefly `src/session/`)      |
| `src/TrustedDevice.ts`                                             | `src/TrustedDevice.ts` (unchanged — briefly `src/session/`)  |
| `src/Session.ts` (compat barrel)                                   | **deleted** — import `SessionService` directly               |
| `src/Password.ts`                                                  | `src/password/Password.ts`                                   |
| `src/PasswordReset.ts`                                             | `src/password/PasswordReset.ts`                              |
| `src/HaveIBeenPwned.ts`                                            | `src/password/HaveIBeenPwned.ts`                             |
| `src/Argon2.ts`                                                    | `src/password/Argon2.ts`                                     |
| `src/Permission.ts`                                                | `src/Permission.ts` (unchanged — briefly `src/authz/`)       |
| `src/Authorization.ts`                                             | `src/Authorization.ts` (unchanged — briefly `src/authz/`)    |
| `src/Rbac.ts`                                                      | `src/RBAC.ts`                                                |
| `src/AuditPlugin.ts`                                               | `src/plugins/Audit.ts`                                       |
| `src/NormalizeEmailPlugin.ts`                                      | `src/plugins/NormalizeEmail.ts`                              |
| `src/RateLimitPlugin.ts`                                           | `src/plugins/RateLimit.ts`                                   |
| `src/AccountLockoutPlugin.ts`                                      | `src/plugins/AccountLockout.ts`                              |
| `src/CaptchaPlugin.ts`                                             | `src/plugins/Captcha.ts`                                     |
| `src/LastLoginMethodPlugin.ts`                                     | `src/plugins/LastLoginMethod.ts`                             |
| `src/IpRateLimitPlugin.ts`                                         | `src/plugins/IPRateLimit.ts`                                 |
| `src/WebAuthnService.ts`                                           | merged into `src/WebAuthn.ts`                                |
| `src/MultiFactorService.ts` (orphaned duplicate of `TwoFactor.ts`) | **deleted**                                                  |
| `src/TwoFactor.ts`                                                 | `src/multifactor/MultiFactor.ts` (renamed — see §8)          |
| `src/OTPSecondFactor.ts`                                           | `src/multifactor/OTPSecondFactor.ts`                         |
| `src/WebAuthn.ts`                                                  | `src/multifactor/WebAuthn.ts`                                |
| `src/OTP.ts`                                                       | `src/multifactor/OTP.ts`                                     |

Flat feature modules that only got acronym-case fixes (still exported from the package root, not
clustered):

| Old file             | New file                                                           |
| -------------------- | ------------------------------------------------------------------ |
| `ApiKey.ts`          | `ApiKey.ts` (unchanged — briefly `APIKey.ts`, see §11)             |
| `ClientIp.ts`        | `ClientIP.ts`                                                      |
| `Jwt.ts`             | `JWT.ts`                                                           |
| `OidcProvider.ts`    | `OidcProvider.ts` (unchanged — briefly `OIDCProvider.ts`, see §11) |
| `OtpSecondFactor.ts` | `OTPSecondFactor.ts`                                               |
| `PhoneOtp.ts`        | `PhoneOTP.ts`                                                      |
| `Sso.ts`             | `SSO.ts`                                                           |
| `Otp.ts`             | `OTP.ts`                                                           |

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
    "./password": { "types": "./dist/password/index.d.ts", "import": "./dist/password/index.js" },
    "./plugins": { "types": "./dist/plugins/index.d.ts", "import": "./dist/plugins/index.js" },
    "./multifactor": {
      "types": "./dist/multifactor/index.d.ts",
      "import": "./dist/multifactor/index.js",
    },
  },
}
```

There is no `./session` subpath (§11) and no `./authz` subpath (§10): both clusters dissolved into
flat `src/` modules covered by the root export.

The root package (`effect-auth`) still re-exports every cluster as a namespace (`Email`, `HTTP`,
`OAuth`, `Password`, `Plugins`, `MultiFactor`) alongside the flat, non-clustered feature modules
(SessionService, JWT, Admin, Organization, …) — no import changes needed there beyond the renames
below.

## 3. Tag-string and identifier acronym fixes

Service tag strings (the `"@effect-auth/…"` string passed to `Context.Service`) and exported type
names now match their class names exactly, with acronyms fully capitalized:

| Old                                                                                                                | New                                                                        |
| ------------------------------------------------------------------------------------------------------------------ | -------------------------------------------------------------------------- |
| `"@effect-auth/ApiKeyService"` / `ApiKeyStore`                                                                     | unchanged — briefly `APIKeyService` / `APIKeyStore`, see §11               |
| `"@effect-auth/ClientIp"`                                                                                          | `ClientIP`                                                                 |
| `"@effect-auth/EmailOtpService"` / `EmailOtpStore` / `EmailOtpUserStore`                                           | `EmailOTPService` / `EmailOTPStore` / `EmailOTPUserStore`                  |
| `"@effect-auth/JwtService"` / `JwtKeyStore`                                                                        | `JWTService` / `JWTKeyStore`                                               |
| `"@effect-auth/OidcClientStore"` / `OidcCodeStore` / `OidcConsentStore` / `OidcTokenStore` / `OidcProviderService` | unchanged — briefly `OIDCClientStore` / … / `OIDCProviderService`, see §11 |
| `"@effect-auth/OtpSecondFactorService"` / `OtpSecondFactorStore`                                                   | `OTPSecondFactorService` / `OTPSecondFactorStore`                          |
| `"@effect-auth/PhoneOtpService"` / `PhoneOtpStore` / `PhoneOtpUserStore`                                           | `PhoneOTPService` / `PhoneOTPStore` / `PhoneOTPUserStore`                  |
| `"@effect-auth/SsoService"` / `SsoProviderStore`                                                                   | `SSOService` / `SSOProviderStore`                                          |
| `"@effect-auth/http/AuthMiddleware"`                                                                               | `"@effect-auth/AuthMiddleware"`                                            |
| `"@effect-auth/http/OptionalAuthMiddleware"`                                                                       | `"@effect-auth/OptionalAuthMiddleware"`                                    |
| `IpResolvableRequest`                                                                                              | `IPResolvableRequest`                                                      |
| `AuthorizationUrlResult`                                                                                           | `AuthorizationURLResult`                                                   |
| `SSOUrlView`                                                                                                       | `SSOURLView`                                                               |
| `HttpIPRateLimitConfig`                                                                                            | `HTTPIPRateLimitConfig`                                                    |

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
| `makeAuthClient`                  | `http/HttpClient.ts`              | `client`                      |
| `makeAuthLifecycleService`        | `AuthLifecycle.ts`                | `make`                        |
| `makeAuthMiddlewareLayer`         | `http/HttpMiddleware.ts`          | `layer`                       |
| `makeOptionalAuthMiddlewareLayer` | `http/HttpMiddleware.ts`          | `optionalLayer`               |
| `makeAuthWebHandler`              | `http/HttpServer.ts`              | `make`                        |
| `makeClientIPLayer`               | `ClientIP.ts`                     | `clientIPLayer`               |
| `makeDeviceAuthorizationService`  | `DeviceAuthorization.ts`          | `make`                        |
| `makeEmailOTPService`             | `email/EmailOTP.ts`               | `make`                        |
| `makeEmailPasswordService`        | `email/EmailPassword.ts`          | `make`                        |
| `makeEmailVerificationService`    | `email/EmailVerification.ts`      | `make`                        |
| `makeGoogleOneTapService`         | `GoogleOneTap.ts`                 | `make`                        |
| `makeInMemoryRoleStore`           | `RBAC.ts`                         | `make`                        |
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
| `makePermission`                  | `Permission.ts`                   | `make`                        |
| `makePhoneOTPService`             | `PhoneOTP.ts`                     | `make`                        |
| `makeRateLimiter`                 | `RateLimit.ts`                    | `make`                        |
| `makeRateLimiterPersistence`      | `RateLimitPersistence.ts`         | `rateLimiterPersistence`      |
| `RateLimiterPersistenceLayer`     | `RateLimitPersistence.ts`         | `rateLimiterPersistenceLayer` |
| `makeRoleBasedPolicy`             | `Authorization.ts`                | `make`                        |
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
shared with `OTPSecondFactor`) were **not** part of this rename — only the TOTP-specific module and
its symbols changed. The directory itself was left as `secondfactor/` at the time; it became
`multifactor/` later, in §11.

## 9. Surrogate-keyed identity: `user.email` → identifiers

Design rationale: `docs/DESIGN.md` § D12. `User` no longer carries
`email`/`emailVerified`; login handles (email, username, phone) are
`Identifier` records with global uniqueness on `(type, value)` behind the
`IdentifierStore` contract.

### API changes

| Old                                                                                        | New                                                                                                        |
| ------------------------------------------------------------------------------------------ | ---------------------------------------------------------------------------------------------------------- |
| `user.email` / `user.emailVerified`                                                        | `IdentifierStore.listByUser(user.id)` + `anyEmail`/`primaryEmail` helpers                                  |
| `UserService.getUserByEmail` / `UserServiceStore.getByEmail`                               | `resolveUserByIdentifier(identifiers, users.get, "email", value)`                                          |
| `UserService.markEmailVerified`                                                            | `IdentifierStore.setVerified(identifier.id, new Date())`                                                   |
| `EmailPasswordStore.getUserByEmail` (also OAuth/MagicLink/EmailOTP/PasswordReset variants) | removed — services resolve via `IdentifierStore`; stores only create users and manage password hashes      |
| `createUser({ email, emailVerified?, ... })` store inputs                                  | `createUser({ name?, image?, attributes? })` — the **service** claims the identifier via `claimIdentifier` |
| `UsernameStore`                                                                            | removed — usernames are `type: "username"` identifiers (created verified)                                  |
| `PhoneOTPUserStore.getUserByPhoneNumber` / `setPhoneNumberVerified`                        | phone identifiers; effectful `getPhoneNumber(identifierStore, userId)`                                     |
| `OrganizationService.acceptInvitation(userId, invitationId, userEmail)`                    | `acceptInvitation(userId, invitationId)` — invitation email checked against the user's identifiers         |
| `OrganizationService.rejectInvitation(invitationId, userEmail)`                            | `rejectInvitation(userId, invitationId)`                                                                   |
| `Auth.HTTP.AuthServices` includes `EmailPasswordStore`                                     | includes `IdentifierStore` instead                                                                         |
| `UserView.email` / `UserView.emailVerified` (required)                                     | optional, derived from the primary/any email identifier; omitted on cookie-cache-served responses          |

New HTTP endpoints: `GET /identifiers` (list the signed-in user's identifiers)
and `DELETE /identifiers/:identifierId` (refuses foreign ids and the account's
last identifier). New test/single-instance helper: `memoryIdentifierStore()`.

### Data migration (sql/alchemy deployments)

`auth_users` drops `email` and `email_verified` (and `auth_users_email_idx`);
`auth_identifiers` becomes the handle table. Backfill **before** deploying the
new schema, then drop the columns:

```sql
-- 1. Backfill: one email identifier per existing user.
INSERT INTO auth_identifiers (id, user_id, type, value, verified, verified_at, created_at)
SELECT
  lower(hex(randomblob(16))),        -- Postgres: gen_random_uuid()::text
  id,
  'email',
  email,
  email_verified,
  CASE WHEN email_verified = 1 THEN updated_at ELSE NULL END,
  created_at
FROM auth_users
WHERE email IS NOT NULL;

-- 2. Then drop the legacy columns/index.
DROP INDEX IF EXISTS auth_users_email_idx;
ALTER TABLE auth_users DROP COLUMN email;
ALTER TABLE auth_users DROP COLUMN email_verified;
```

If your app stored phone numbers in `attributes.phoneNumber` (the old PhoneOTP
convention), backfill those as `type = 'phone'` identifiers with
`verified = attributes.phoneNumberVerified` the same way, then remove the
attribute keys. Username deployments backfill from wherever the old
`UsernameStore` implementation kept its mapping, with `verified = 1`.

## 10. Authorization is flat: the `authz/` cluster dissolved

Authorization is a first-class feature, not a side cluster, so the `authz`
abbreviation is gone everywhere and `src/authz/` dissolved into flat top-level
modules. `Auth.Authz.X` is now `Auth.X` (or, for the policy kernel's
data-shaped modules, still a namespace — just one hop shallower:
`Auth.Policy.permit`, `Auth.Entity.ref`, `Auth.Condition.eq`).

The `./authz` subpath export was **removed with no replacement** — the root
barrel covers everything it exported. `import { ... } from
"@thomasfosterau/effect-auth/authz"` becomes `import { ... } from
"@thomasfosterau/effect-auth"`.

| Old                                   | New                                        |
| ------------------------------------- | ------------------------------------------ |
| `src/authz/*.ts`                      | `src/*.ts` (flat)                          |
| `src/authz/Model.ts`                  | `src/AuthorizationModel.ts`                |
| `src/http/AuthzMiddleware.ts`         | `src/http/AuthorizationMiddleware.ts`      |
| `"@thomasfosterau/effect-auth/authz"` | `"@thomasfosterau/effect-auth"` (root)     |
| `Auth.Authz.RoleStore`                | `Auth.RoleStore`                           |
| `Auth.Authz.AuthorizationPolicy`      | `Auth.AuthorizationPolicy`                 |
| `Auth.Authz.requirePermission`        | `Auth.requirePermission`                   |
| `Auth.Authz.protectedField`           | `Auth.protectedField`                      |
| `Auth.Authz.Authorizer`               | `Auth.Authorizer`                          |
| `Auth.Authz.Policy.permit`            | `Auth.Policy.permit`                       |
| `Auth.Authz.Entity.ref`               | `Auth.Entity.ref`                          |
| `Auth.Authz.Model.validatePolicies`   | `Auth.AuthorizationModel.validatePolicies` |
| `makeAuthzMiddleware`                 | `makeAuthorizationMiddleware`              |
| `AuthzMiddlewareClass`                | `AuthorizationMiddlewareClass`             |
| `AuthzInput`                          | `AuthorizationMiddlewareInput`             |

The middleware tag-id prefix changed from `"@effect-auth/AuthzMiddleware#"` to
`"@effect-auth/AuthorizationMiddleware#"`; ids stay per-instance and are not
part of the public contract.

`AuthorizationMiddlewareInput` is deliberately _not_ named `AuthorizationInput`:
`AuthorizeInput` (the `Authorizer`'s own request shape) already exists at the
root, and the two must stay distinguishable.

## 11. Pascal-case acronyms, `multifactor/`, and the flat session spine

Four PR-review follow-ups, all mechanical.

### 11.1 `OIDCProvider` → `OidcProvider`

Effect's own convention writes a leading acronym as a Pascal-case word
(`HttpApi`, not `HTTPApi` — §1's http-layer file renames), so the OIDC provider
module follows it: `src/OIDCProvider.ts` → `src/OidcProvider.ts`, with every
`OIDC`-prefixed identifier in that module respelled `Oidc`. §3 had briefly gone
the other way; this supersedes it.

| Old                                                                                                                                    | New                                                                                                                    |
| -------------------------------------------------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------- |
| `src/OIDCProvider.ts`                                                                                                                  | `src/OidcProvider.ts`                                                                                                  |
| `"@effect-auth/OIDCProviderService"` (and the `OIDCClientStore` / `OIDCCodeStore` / `OIDCTokenStore` / `OIDCConsentStore` tag strings) | `"@effect-auth/OidcProviderService"` (and `OidcClientStore` / `OidcCodeStore` / `OidcTokenStore` / `OidcConsentStore`) |
| `OIDCProviderService`, `OIDCProviderConfig`                                                                                            | `OidcProviderService`, `OidcProviderConfig`                                                                            |
| `OIDCProviderError`, `OIDCTokenError`, `OIDCRegistrationError`                                                                         | `OidcProviderError`, `OidcTokenError`, `OidcRegistrationError`                                                         |
| `OIDCClient`, `OIDCClientStore`, `OIDCClientMetadata`, `NormalizedOIDCClientMetadata`                                                  | `OidcClient`, `OidcClientStore`, `OidcClientMetadata`, `NormalizedOidcClientMetadata`                                  |
| `OIDCAuthorizationCode`, `OIDCCodeStore`, `OIDCConsent`, `OIDCConsentStore`                                                            | `OidcAuthorizationCode`, `OidcCodeStore`, `OidcConsent`, `OidcConsentStore`                                            |
| `OIDCToken`, `OIDCTokenStore`, `OIDCTokenEndpointAuthMethod`                                                                           | `OidcToken`, `OidcTokenStore`, `OidcTokenEndpointAuthMethod`                                                           |
| `OIDCAuthorizeRequest`, `OIDCAuthorizeResult`, `OIDCTokenRequest`, `OIDCTokenResult`                                                   | `OidcAuthorizeRequest`, `OidcAuthorizeResult`, `OidcTokenRequest`, `OidcTokenResult`                                   |
| `RegisterOIDCClientInput`, `RegisteredOIDCClient`, `UpdateOIDCClientInput`, `TrustedOIDCClient`                                        | `RegisterOidcClientInput`, `RegisteredOidcClient`, `UpdateOidcClientInput`, `TrustedOidcClient`                        |
| `OIDCRegistrationPolicy`, `OIDCRegistrationDisposition`, `OIDCInitialAccessTokenVerifier`                                              | `OidcRegistrationPolicy`, `OidcRegistrationDisposition`, `OidcInitialAccessTokenVerifier`                              |
| `OIDCDynamicRegistrationConfig`, `OIDCDynamicRegistrationInfo`, `DynamicallyRegisteredOIDCClient`                                      | `OidcDynamicRegistrationConfig`, `OidcDynamicRegistrationInfo`, `DynamicallyRegisteredOidcClient`                      |
| `hashOIDCSecret`                                                                                                                       | `hashOidcSecret`                                                                                                       |
| `recordOIDCTokenRequest` (`Observability.ts`)                                                                                          | `recordOidcTokenRequest`                                                                                               |
| `OIDCClientView`, `OIDCClientCreatedView`, `OIDCClientListView`, `OIDCClientUpdatePayload` (wire)                                      | `OidcClientView`, `OidcClientCreatedView`, `OidcClientListView`, `OidcClientUpdatePayload`                             |
| `OIDCConsentPayload`, `OIDCRedirectView`, `OIDCTokenPayload`, `OIDCTokenView` (wire)                                                   | `OidcConsentPayload`, `OidcRedirectView`, `OidcTokenPayload`, `OidcTokenView`                                          |
| `OIDCRegisterClientPayload`, `OIDCRegistrationPayload`, `OIDCRegistrationView` (wire)                                                  | `OidcRegisterClientPayload`, `OidcRegistrationPayload`, `OidcRegistrationView`                                         |

Unchanged: the `SCREAMING_SNAKE_CASE` constants keep the acronym as a whole word
(`DEFAULT_OIDC_SCOPES`, `DEFAULT_OIDC_REGISTRATION_RATE_LIMIT`,
`OIDC_TOKEN_ENDPOINT_AUTH_METHODS`, `OIDC_DYNAMIC_GRANT_TYPES`,
`OIDC_DYNAMIC_RESPONSE_TYPES`); so do the client SDK's `client.oidc.*` methods,
every HTTP path and operationId, and the metric
`effect-auth.oidc_token_requests.total`. `SSO.ts`'s `OIDCSSOProvider` (with its
`OIDCSSOProviderView` / `SSORegisterOIDCPayload` wire schemas) also stays as it
is — it is an SSO type, and `SSO.ts` was not part of this round.

### 11.2 `APIKey` → `ApiKey`

The same convention, applied to the API-key module: `src/APIKey.ts` →
`src/ApiKey.ts`. §3 had briefly gone the other way; this supersedes it.

| Old                                                                               | New                                                                               |
| --------------------------------------------------------------------------------- | --------------------------------------------------------------------------------- |
| `src/APIKey.ts`                                                                   | `src/ApiKey.ts`                                                                   |
| `"@effect-auth/APIKeyService"`, `"@effect-auth/APIKeyStore"`                      | `"@effect-auth/ApiKeyService"`, `"@effect-auth/ApiKeyStore"`                      |
| `APIKeyService`, `APIKeyStore`, `APIKeyError`, `APIKeyConfig`                     | `ApiKeyService`, `ApiKeyStore`, `ApiKeyError`, `ApiKeyConfig`                     |
| `APIKey` (the record type)                                                        | `ApiKey`                                                                          |
| `APIKeyCreateOptions`, `APIKeyCreateResult`, `APIKeyVerifyResult`, `APIKeyUpdate` | `ApiKeyCreateOptions`, `ApiKeyCreateResult`, `ApiKeyVerifyResult`, `ApiKeyUpdate` |
| `hashAPIKey`                                                                      | `hashApiKey`                                                                      |
| `APIKeyView`, `APIKeyCreatedView`, `APIKeyListView` (wire)                        | `ApiKeyView`, `ApiKeyCreatedView`, `ApiKeyListView`                               |
| `APIKeyCreatePayload`, `APIKeyUpdatePayload`, `APIKeyRateLimit` (wire)            | `ApiKeyCreatePayload`, `ApiKeyUpdatePayload`, `ApiKeyRateLimit`                   |

Unchanged: the client SDK's `client.apiKeys.*` methods, the `/api-key/*` paths
and their `apiKey*` operationIds.

### 11.3 `secondfactor/` → `multifactor/`

The cluster is named after the feature it ships (`MultiFactorService`), not after
the position of the factor in the flow.

| Old                                          | New                                         |
| -------------------------------------------- | ------------------------------------------- |
| `src/secondfactor/*`                         | `src/multifactor/*`                         |
| `"@thomasfosterau/effect-auth/secondfactor"` | `"@thomasfosterau/effect-auth/multifactor"` |
| `Auth.SecondFactor.X`                        | `Auth.MultiFactor.X`                        |

The module files inside keep their names (`MultiFactor.ts`,
`OTPSecondFactor.ts`, `WebAuthn.ts`, `OTP.ts`), as do every exported identifier,
tag string, HTTP route and wire schema in them — including the deliberately
second-factor-specific `OTPSecondFactor*` symbols and the generic
`SecondFactorGate` / `SecondFactorChallenge` seam in `email/EmailPassword.ts`.
There was no collision at the root: nothing else exports the name `MultiFactor`.

### 11.4 The `session/` cluster dissolved

Session management is the spine nearly every feature module depends on, not a
side cluster, so — exactly as with `authz/` in §10 — `src/session/` dissolved
into flat top-level modules and the `./session` subpath was **removed with no
replacement**. `import { ... } from "@thomasfosterau/effect-auth/session"`
becomes `import { ... } from "@thomasfosterau/effect-auth"`.

| Old                                     | New                                         |
| --------------------------------------- | ------------------------------------------- |
| `src/session/SessionService.ts`         | `src/SessionService.ts`                     |
| `src/session/SessionStore.ts`           | `src/SessionStore.ts`                       |
| `src/session/UserStore.ts`              | `src/UserStore.ts`                          |
| `src/session/TrustedDevice.ts`          | `src/TrustedDevice.ts`                      |
| `src/session/index.ts`                  | **deleted** — dissolved into `src/index.ts` |
| `"@thomasfosterau/effect-auth/session"` | `"@thomasfosterau/effect-auth"` (root)      |

`SessionService`, `SessionStore`, `UserStore` and `UserServiceStore` were already
re-exported flat from the root, so they are unaffected. The `TrustedDevice`
symbols were reachable **only** through the `./session` subpath before; they now
sit on the flat spine:

| Old                                                                      | New                                                       |
| ------------------------------------------------------------------------ | --------------------------------------------------------- |
| `TrustedDeviceStore` (from `.../effect-auth/session`)                    | `Auth.TrustedDeviceStore`                                 |
| `TrustedDeviceService`                                                   | `Auth.TrustedDeviceService`                               |
| `TrustedDeviceRecord`, `TrustedDeviceConfig`, `TrustedDeviceIssueResult` | `Auth.TrustedDeviceRecord`, …                             |
| `TrustedDeviceCookieRef`, `trustedDeviceConfig`                          | `Auth.TrustedDeviceCookieRef`, `Auth.trustedDeviceConfig` |
| `TrustedDeviceWithMultiFactorGateLayer`                                  | `Auth.TrustedDeviceWithMultiFactorGateLayer`              |
| `gate`                                                                   | `Auth.TrustedDevice.gate`                                 |

`make` and `gate` are too generic to sit at the root, so `TrustedDevice.ts` is
_also_ re-exported as the namespace `Auth.TrustedDevice` — the same treatment
`Auth.PolicyStore` got in §10. There is still no `Auth.Session` namespace, for
the reason recorded in the root barrel's module comment: `Types.ts` owns that
name for the flat `Session` record.

## Validation

- `vp check`, `bunx tsc --noEmit`, `vp test --typecheck --run` — all green
- `packages/client` typechecks against the new API
- `grep -rn 'from "\./.*\.js"' src/ packages/` — no matches
- `grep -rnE "export const make[A-Z]" src/` — no matches
