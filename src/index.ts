/**
 * effect-auth — public API barrel.
 *
 * Curated root: a flat core spine (types, errors, hooks, session services,
 * plugin infrastructure, crypto/rate-limit primitives) plus flat feature
 * modules that haven't earned a cluster of their own, plus namespace
 * re-exports for each cluster (`Email`, `HTTP`, `OAuth`, `Password`,
 * `Plugins`, `Authz`). Clustered modules are reachable through their
 * namespace (`Auth.Email.EmailOTPService`) or subpath (`effect-auth/email`)
 * — they are not flattened into the root.
 *
 * No `Session` namespace: `Types.ts` already exports the flat `Session`
 * record type/schema (`export * from "./Types.ts"` above), and a sibling
 * `export * as Session from "./session/index.ts"` would silently win the
 * name collision, making the `Session` type unreachable from the root for
 * every consumer that types a session as `Auth.Session`. The session
 * cluster (`SessionService`, `SessionStore`, `UserStore`, `TrustedDevice`)
 * stays reachable via the flat spine below and the `effect-auth/session`
 * subpath.
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
export * from "./Messages.ts";

// Session services
export * from "./session/SessionService.ts";
export * from "./session/SessionStore.ts";
export * from "./session/UserStore.ts";

// Rate limiting
export * from "./RateLimit.ts";
export * from "./RateLimitPersistence.ts";

// OTP primitives
export * from "./OTP.ts";

// Key-value store adapters
export * from "./KeyValueStores.ts";

// Shared internal utilities
export * from "./utils.ts";

// Observability
/** Metrics counters and record helpers for tracing and observability. */
export * from "./Observability.ts";

// Flat feature modules
export * from "./User.ts";
export * from "./PhoneOTP.ts";
export * from "./MagicLink.ts";
export * from "./Username.ts";
export * from "./TwoFactor.ts";
export * from "./WebAuthn.ts";
export * from "./APIKey.ts";
export * from "./JWT.ts";
export * from "./SSO.ts";
export * from "./GoogleOneTap.ts";
export * from "./Anonymous.ts";
export * from "./Admin.ts";
export * from "./Organization.ts";
export * from "./AccountManagement.ts";
export * from "./DeviceAuthorization.ts";
export * from "./AuthLifecycle.ts";
export * from "./OIDCProvider.ts";
export * from "./ClientIP.ts";
export * from "./SessionCookieCache.ts";
export {
  type OneTimeTokenRecord,
  OneTimeTokenStore,
  type OneTimeTokenStoreShape,
  type OneTimeTokenConfig,
  type OneTimeTokenGenerateOptions,
  type OneTimeTokenVerifyResult,
  type OneTimeTokenServiceShape,
  OneTimeTokenService,
  redeemOneTimeTokenForSession,
} from "./OneTimeToken.ts";

// Cluster namespaces
export * as Email from "./email/index.ts";
export * as HTTP from "./http/index.ts";
export * as OAuth from "./oauth/index.ts";
export * as Password from "./password/index.ts";
export * as Plugins from "./plugins/index.ts";
export * as Authz from "./authz/index.ts";
