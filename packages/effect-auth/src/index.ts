/**
 * effect-auth — public API barrel.
 *
 * No `Session` namespace: `Types.ts` already exports the flat `Session`
 * record type/schema (`export * from "./Types.ts"` above), and a sibling
 * `export * as Session from "./session/index.ts"` would silently win that
 * name collision — an explicit `export * as X` always beats an ambiguous
 * `export *`-derived binding of the same name — making `Types.Session`
 * unreachable from the root for every consumer that types a session as
 * `Auth.Session`. The session cluster (`SessionService`, `SessionStore`,
 * `UserStore`, `TrustedDevice`) stays reachable via the flat spine below
 * and the `effect-auth/session` subpath.
 *
 * @module effect-auth
 */

// Core primitives
export * from "./Types.ts";
export * from "./Errors.ts";
export * from "./Hooks.ts";
export * from "./TokenHash.ts";
export * from "./Identifier.ts";
export * from "./Cipher.ts";
export * from "./Delivery.ts";
export * from "./Messages.ts";
export * from "./utils.ts";

// Session management (core — depended on by nearly every feature module)
export { SessionService } from "./session/SessionService.ts";
export * from "./session/SessionStore.ts";
export * from "./session/UserStore.ts";

// Rate limiting facade
export {
  type RateLimitConfig,
  type RateLimitEntry,
  RateLimitStore,
  RateLimiter,
  RateLimitPresets,
} from "./RateLimit.ts";
export * from "./RateLimitPersistence.ts";

// Key-value store adapters
export * from "./KeyValueStores.ts";

// Core user service
export { UserServiceStore, type UpdateUserInput, UserService } from "./User.ts";

// Feature modules
export {
  PhoneOTPError,
  type PhoneOTPPurpose,
  type PhoneOTPRecord,
  PhoneOTPStore,
  type PhoneOTPCreateUserInput,
  PhoneOTPUserStore,
  type PhoneOTPConfig,
  type PhoneOTPSignInOptions,
  type PhoneOTPAuthResult,
  PhoneOTPService,
  getPhoneNumber,
} from "./PhoneOTP.ts";
export {
  type MagicLinkToken,
  type MagicLinkCreateUserInput,
  MagicLinkStore,
  MagicLinkUserStore,
  type MagicLinkConfig,
  type MagicLinkVerifyOptions,
  type MagicLinkResult,
  MagicLinkService,
  generateMagicLinkToken,
} from "./MagicLink.ts";
export {
  UsernameError,
  type UsernameConfig,
  type UsernameSignUpInput,
  type UsernameSignInInput,
  UsernameService,
} from "./Username.ts";
export {
  APIKeyError,
  type APIKey,
  APIKeyStore,
  type APIKeyConfig,
  type APIKeyCreateOptions,
  type APIKeyCreateResult,
  type APIKeyVerifyResult,
  type APIKeyUpdate,
  APIKeyService,
  hashAPIKey,
} from "./APIKey.ts";
export {
  JWTError,
  type JWTAlgorithm,
  type JWTKeyPair,
  JWTKeyStore,
  type JWTConfig,
  type JWTSignResult,
  type Jwks,
  JWTService,
  jwtServiceConfig,
  generateKeyPair,
  type RemoteJwksConfig,
  RemoteJwksVerifier,
  remoteJwksVerifier,
} from "./JWT.ts";
export {
  SSOError,
  type SSOProvider,
  SSOProviderStore,
  type RegisterProviderInput,
  type SSOSignInResult,
  type SSOSignInSelector,
  SSOService,
  type SSOConfig,
} from "./SSO.ts";
export {
  GoogleOneTapError,
  GOOGLE_JWKS_ENDPOINT,
  GOOGLE_ISSUERS,
  type GoogleOneTapNonceEntry,
  GoogleOneTapNonceStore,
  type GoogleOneTapConfig,
  type GoogleOneTapSignInResult,
  GoogleOneTapService,
} from "./GoogleOneTap.ts";
export {
  AnonymousUserStore,
  type AnonymousConfig,
  type AnonymousResult,
  AnonymousService,
  isAnonymousUser,
} from "./Anonymous.ts";
export {
  AdminError,
  type ListUsersQuery,
  type ListUsersResult,
  type AdminCreateUserInput,
  AdminUserStore,
  type AdminConfig,
  isAdmin,
  isBanned,
  type BanUserOptions,
  AdminService,
  BannedUserPlugin,
} from "./Admin.ts";
export {
  OrganizationError,
  type Organization,
  type Member,
  type InvitationStatus,
  type Invitation,
  defaultOrganizationRoles,
  OrganizationStore,
  type OrganizationConfig,
  type CreateOrganizationInput,
  type UpdateOrganizationInput,
  type InviteMemberInput,
  type FullOrganization,
  OrganizationService,
} from "./Organization.ts";
export {
  type AccountTokenPurpose,
  type AccountToken,
  AccountManagementStore,
  AccountTokenError,
  type AccountManagementConfig,
  type EmailChangeResult,
  AccountManagementService,
} from "./AccountManagement.ts";
export {
  type DeviceAuthorizationStatus,
  type DeviceAuthorizationRecord,
  DeviceAuthorizationStore,
  DevicePollError,
  DeviceCodeError,
  type DeviceAuthorizationConfig,
  type DeviceBeginResult,
  type DevicePollResult,
  DeviceAuthorizationService,
  normalizeUserCode,
} from "./DeviceAuthorization.ts";
export {
  type AuthLifecycleConfig,
  type AuthLifecycleResult,
  type VerifyEmailInput,
  AuthLifecycleService,
} from "./AuthLifecycle.ts";
export {
  OIDCProviderError,
  OIDCTokenError,
  type OIDCClient,
  OIDCClientStore,
  type OIDCAuthorizationCode,
  OIDCCodeStore,
  type OIDCToken,
  OIDCTokenStore,
  type OIDCConsent,
  OIDCConsentStore,
  type RegisterOIDCClientInput,
  type RegisteredOIDCClient,
  type UpdateOIDCClientInput,
  type OIDCAuthorizeRequest,
  type OIDCAuthorizeResult,
  type OIDCTokenRequest,
  type OIDCTokenResult,
  type TrustedOIDCClient,
  type OIDCProviderConfig,
  OIDCProviderService,
  hashOIDCSecret,
  DEFAULT_OIDC_SCOPES,
} from "./OIDCProvider.ts";
export * from "./ClientIP.ts";
export * from "./SessionCookieCache.ts";
export {
  type OneTimeTokenRecord,
  OneTimeTokenStore,
  type OneTimeTokenConfig,
  type OneTimeTokenGenerateOptions,
  type OneTimeTokenVerifyResult,
  OneTimeTokenService,
  redeemOneTimeTokenForSession,
} from "./OneTimeToken.ts";

// Observability
/** Metrics counters and record helpers for tracing and observability. */
export * from "./Observability.ts";

// Cluster namespaces (also available as `effect-auth/<cluster>` subpaths)
export * as Email from "./email/index.ts";
export * as HTTP from "./http/index.ts";
export * as OAuth from "./oauth/index.ts";
export * as Password from "./password/index.ts";
export * as Plugins from "./plugins/index.ts";
export * as Authz from "./authz/index.ts";
export * as SecondFactor from "./secondfactor/index.ts";
