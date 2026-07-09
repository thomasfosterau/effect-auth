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
export * from "./Messages.ts";
export * from "./utils.ts";

// Session management (core — depended on by nearly every feature module)
export * from "./session/SessionService.ts";
export * from "./session/SessionStore.ts";
export * from "./session/UserStore.ts";

// Rate limiting facade
export * from "./RateLimit.ts";
export * from "./RateLimitPersistence.ts";

// Key-value store adapters
export * from "./KeyValueStores.ts";

// OTP primitives
export * from "./OTP.ts";

// Core user service
export * from "./User.ts";

// Feature modules
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
