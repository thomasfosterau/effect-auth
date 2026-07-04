import { Context, Effect, FileSystem, Layer, Option, Path } from "effect";
import { resolveMessage } from "./Messages.ts";
import { HttpApiBuilder } from "effect/unstable/httpapi";
import {
  Etag,
  HttpPlatform,
  HttpRouter,
  HttpServerRequest,
  HttpServerResponse,
} from "effect/unstable/http";
import { AuthApi, getOpenApiSpec } from "./HttpApi.ts";
import { ClientIp, resolveClientIp, type TrustedProxyConfig } from "./ClientIp.ts";
import { RateLimiter, RateLimitStore, type RateLimitConfig } from "./RateLimit.ts";
import * as S from "./HttpApiSchemas.ts";
import { AuthLifecycleService } from "./AuthLifecycle.ts";
import { Hooks } from "./Hooks.ts";
import { SessionManager, UserStore } from "./Session.ts";
import { EmailPasswordStore, makeEmailPasswordService } from "./EmailPassword.ts";
import { MagicLinkService, MagicLinkStore, MagicLinkUserStore } from "./MagicLink.ts";
import { AccountManagementService, AccountManagementStore } from "./AccountManagement.ts";
import { AnonymousService, AnonymousUserStore } from "./Anonymous.ts";
import { PhoneOtpService, PhoneOtpStore, PhoneOtpUserStore } from "./PhoneOtp.ts";
import { UsernameService, UsernameStore } from "./Username.ts";
import { DeviceAuthorizationService, DeviceAuthorizationStore } from "./DeviceAuthorization.ts";
import { EmailOtpService, EmailOtpStore, EmailOtpUserStore } from "./EmailOtp.ts";
import { PendingTwoFactorStore, TwoFactorService, TwoFactorStore } from "./TwoFactor.ts";
import { PasswordHasher } from "./Password.ts";
import { EmailVerificationService, EmailVerificationStore } from "./EmailVerification.ts";
import {
  PasswordResetService,
  PasswordResetStore,
  PasswordResetUserStore,
} from "./PasswordReset.ts";
import { UserServiceStore, UserService } from "./User.ts";
import {
  OrganizationService,
  OrganizationStore,
  type Organization,
  type Member,
  type Invitation,
  type FullOrganization,
} from "./Organization.ts";
import { AdminService, AdminUserStore, isAdmin } from "./Admin.ts";
import { ApiKeyService, ApiKeyStore, type ApiKey } from "./ApiKey.ts";
import { JwtService, JwtKeyStore } from "./Jwt.ts";
import {
  OidcProviderService,
  OidcClientStore,
  OidcCodeStore,
  OidcTokenStore,
  OidcConsentStore,
  type OidcClient,
} from "./OidcProvider.ts";
import { SsoService, SsoProviderStore, type SsoProvider } from "./Sso.ts";
import { OAuthStateStore, OAuthUserStore } from "./OAuth.ts";
import { hashToken } from "./TokenHash.ts";
import { GoogleOneTapNonceStore, GoogleOneTapService } from "./GoogleOneTap.ts";
import {
  decodeSessionCacheCookie,
  encodeSessionCacheCookie,
  resolveSessionCache,
  type ResolvedSessionCache,
  type SessionCacheConfig,
} from "./SessionCookieCache.ts";
import type * as Types from "./Types.ts";

/**
 * The services the auth handlers require. Your `services` layer must provide
 * all of these (a superset is fine). They are the existing core services plus
 * the stores the orchestration services depend on, plus the `Hooks` service
 * (provide `Hooks.Default` for no-op hooks, or a `composePlugins([...])` stack).
 */
export type AuthServices =
  | AuthLifecycleService
  | SessionManager
  | EmailPasswordStore
  | PasswordHasher
  | EmailVerificationService
  | EmailVerificationStore
  | PasswordResetService
  | PasswordResetStore
  | PasswordResetUserStore
  | UserService
  | UserServiceStore
  | Hooks;

/**
 * Server implementation for the auth HTTP contract.
 *
 * `makeAuthWebHandler` turns the contract + your service layer into a standard
 * Web `Request => Response` handler that any framework can mount. Handlers call
 * the existing Effect services; the session cookie and session resolution are
 * handled here so framework integrations no longer hand-roll them.
 */

// -----------------------------------------------------------------------------
// Cookie configuration
// -----------------------------------------------------------------------------

export interface CookieConfig {
  /** Cookie name. Default `conduit_session`. */
  readonly name?: string;
  /** Mark the cookie `Secure`. Default `true` (set `false` for local http). */
  readonly secure?: boolean;
  /** Cookie path. Default `/`. */
  readonly path?: string;
  /**
   * Apply the `__Host-` cookie name prefix for added security. When active the
   * browser enforces that the cookie is `Secure`, has no `Domain` attribute,
   * and has `Path=/`. Defaults to `true` when `secure` is `true` and `path`
   * is `/` (or not set). Set to `false` to opt out.
   *
   * Note: enabling this when `path` is not `/` forces the cookie path to `/`
   * so the prefix constraint is satisfied.
   */
  readonly hostPrefix?: boolean;
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

/** Multiple concurrent accounts per client (device-scoped session list). */
export interface MultiSessionConfig {
  /** Maximum concurrent sessions retained per device. Default 5. */
  readonly maximumSessions?: number;
}

interface ResolvedCookieConfig {
  readonly name: string;
  readonly secure: boolean;
  readonly path: string;
  readonly cache: ResolvedSessionCache | undefined;
  readonly multiSession: { readonly maximumSessions: number } | undefined;
  readonly lastLoginMethod: { readonly maxAge: number } | undefined;
}

const resolveCookieConfig = (
  config?: CookieConfig,
  multiSession?: MultiSessionConfig,
): ResolvedCookieConfig => {
  const secureCookies = config?.secure ?? true;
  const configuredPath = config?.path ?? "/";
  // Apply __Host- prefix by default when secure and path is root; the prefix
  // forces path=/ so browsers enforce host-binding (no Domain, Secure, Path=/).
  const useHostPrefix = config?.hostPrefix ?? (secureCookies && configuredPath === "/");
  const baseName = config?.name ?? "conduit_session";
  const effectiveName = useHostPrefix && secureCookies ? `__Host-${baseName}` : baseName;
  // __Host- cookies must have Path=/; override whatever path was configured.
  const effectivePath = useHostPrefix && secureCookies ? "/" : configuredPath;
  return {
    name: effectiveName,
    secure: secureCookies,
    path: effectivePath,
    cache: resolveSessionCache(config?.cache),
    multiSession:
      multiSession === undefined
        ? undefined
        : { maximumSessions: multiSession.maximumSessions ?? 5 },
    lastLoginMethod:
      config?.lastLoginMethod === undefined || config.lastLoginMethod === false
        ? undefined
        : {
            maxAge:
              (config.lastLoginMethod === true ? undefined : config.lastLoginMethod.maxAge) ??
              30 * 24 * 60 * 60 * 1000,
          },
  };
};

/** Name of the non-httpOnly last-login-method hint cookie. */
const lastMethodCookieName = (cfg: ResolvedCookieConfig): string => `${cfg.name}_last_method`;

/** Options for the last-login-method hint cookie: readable by page scripts. */
const lastMethodCookieOptions = (cfg: ResolvedCookieConfig, maxAge: number) =>
  ({
    httpOnly: false,
    sameSite: "lax",
    secure: cfg.secure,
    path: cfg.path,
    maxAge: Math.floor(maxAge / 1000),
  }) as const;

/** Name of the device session-list cookie. */
const multiCookieName = (cfg: ResolvedCookieConfig): string => `${cfg.name}_multi`;

/** Parse the comma-separated device session-id list from the request. */
const readDeviceSessionIds = (
  request: HttpServerRequest.HttpServerRequest,
  cfg: ResolvedCookieConfig,
): string[] => {
  const raw = request.cookies[multiCookieName(cfg)];
  if (raw === undefined || raw === "") return [];
  // "." separates ids: safe inside a cookie value (session ids are hex /
  // base64url) and, unlike ",", it doesn't confuse Set-Cookie parsing.
  return raw.split(".").filter((id) => id.length > 0);
};

/** Name of the companion cache cookie. */
const dataCookieName = (cfg: ResolvedCookieConfig): string => `${cfg.name}_data`;

const dataCookieOptions = (cfg: ResolvedCookieConfig, cache: ResolvedSessionCache) =>
  ({
    httpOnly: true,
    sameSite: "lax",
    secure: cfg.secure,
    path: cfg.path,
    maxAge: Math.floor(cache.maxAge / 1000),
  }) as const;

const sessionCookieOptions = (cfg: ResolvedCookieConfig, expiresAt: Date) =>
  ({
    httpOnly: true,
    sameSite: "lax",
    secure: cfg.secure,
    path: cfg.path,
    expires: expiresAt,
  }) as const;

/** Options for a browser-session cookie (cleared on browser close, no Max-Age/Expires). */
const sessionOnlyCookieOptions = (cfg: ResolvedCookieConfig) =>
  ({
    httpOnly: true,
    sameSite: "lax",
    secure: cfg.secure,
    path: cfg.path,
  }) as const;

const clearCookieOptions = (cfg: ResolvedCookieConfig) =>
  ({
    httpOnly: true,
    sameSite: "lax",
    secure: cfg.secure,
    path: cfg.path,
    maxAge: 0,
  }) as const;

// -----------------------------------------------------------------------------
// Session resolution (Authorization header, then cookie)
// -----------------------------------------------------------------------------

const sessionIdFromRequest = (
  request: HttpServerRequest.HttpServerRequest,
  cfg: ResolvedCookieConfig,
): string | undefined => {
  const auth = request.headers["authorization"];
  if (auth) {
    const [scheme, value] = auth.split(" ");
    if ((scheme === "Token" || scheme === "Bearer") && value) return value;
  }
  return request.cookies[cfg.name];
};

// -----------------------------------------------------------------------------
// Handlers
// -----------------------------------------------------------------------------

const signUpInput = (payload: S.SignUpPayload) => ({
  email: payload.email,
  password: payload.password,
  ...(payload.name !== undefined && { name: payload.name }),
  ...(payload.attributes !== undefined && { attributes: payload.attributes }),
  ...(payload.captchaToken !== undefined && { captchaToken: payload.captchaToken }),
});

// -----------------------------------------------------------------------------
// Optional feature resolution
//
// Magic link, email OTP and two-factor are optional plugins: their services
// are NOT part of `AuthServices`. Handlers resolve them with
// `Effect.serviceOption` and answer 404 when absent. Because the service
// METHODS declare their store requirements in `R`, the store tags are
// resolved optionally too and provided into each method call, keeping the
// handlers' `R` inside `AuthServices`.
// -----------------------------------------------------------------------------

/** Resolve the magic link service + stores, or fail with 404. */
const resolveMagicLink = Effect.gen(function* () {
  const service = yield* Effect.serviceOption(MagicLinkService);
  const store = yield* Effect.serviceOption(MagicLinkStore);
  const userStore = yield* Effect.serviceOption(MagicLinkUserStore);
  if (Option.isNone(service) || Option.isNone(store) || Option.isNone(userStore)) {
    return yield* new S.NotFound({ message: "Magic link is not enabled" });
  }
  const provideStores = <A, E, R>(effect: Effect.Effect<A, E, R>) =>
    effect.pipe(
      Effect.provideService(MagicLinkStore, store.value),
      Effect.provideService(MagicLinkUserStore, userStore.value),
    );
  return { service: service.value, provideStores };
});

/** Resolve the email OTP service + stores, or fail with 404. */
const resolveEmailOtp = Effect.gen(function* () {
  const service = yield* Effect.serviceOption(EmailOtpService);
  const store = yield* Effect.serviceOption(EmailOtpStore);
  const userStore = yield* Effect.serviceOption(EmailOtpUserStore);
  if (Option.isNone(service) || Option.isNone(store) || Option.isNone(userStore)) {
    return yield* new S.NotFound({ message: "Email OTP is not enabled" });
  }
  const provideStores = <A, E, R>(effect: Effect.Effect<A, E, R>) =>
    effect.pipe(
      Effect.provideService(EmailOtpStore, store.value),
      Effect.provideService(EmailOtpUserStore, userStore.value),
    );
  return { service: service.value, provideStores };
});

/** Resolve the two-factor service + stores, or fail with 404. */
const resolveTwoFactor = Effect.gen(function* () {
  const service = yield* Effect.serviceOption(TwoFactorService);
  const store = yield* Effect.serviceOption(TwoFactorStore);
  const pendingStore = yield* Effect.serviceOption(PendingTwoFactorStore);
  if (Option.isNone(service) || Option.isNone(store) || Option.isNone(pendingStore)) {
    return yield* new S.NotFound({ message: "Two-factor authentication is not enabled" });
  }
  const provideStores = <A, E, R>(effect: Effect.Effect<A, E, R>) =>
    effect.pipe(
      Effect.provideService(TwoFactorStore, store.value),
      Effect.provideService(PendingTwoFactorStore, pendingStore.value),
    );
  return { service: service.value, provideStores };
});

/** Resolve the account-management service + store, or fail with 404. */
const resolveAccountManagement = Effect.gen(function* () {
  const service = yield* Effect.serviceOption(AccountManagementService);
  const store = yield* Effect.serviceOption(AccountManagementStore);
  if (Option.isNone(service) || Option.isNone(store)) {
    return yield* new S.NotFound({ message: "Account management is not enabled" });
  }
  const provideStores = <A, E, R>(effect: Effect.Effect<A, E, R>) =>
    effect.pipe(Effect.provideService(AccountManagementStore, store.value));
  return { service: service.value, provideStores };
});

/** Resolve the device-authorization service + store, or fail with 404. */
const resolveDevice = Effect.gen(function* () {
  const service = yield* Effect.serviceOption(DeviceAuthorizationService);
  const store = yield* Effect.serviceOption(DeviceAuthorizationStore);
  if (Option.isNone(service) || Option.isNone(store)) {
    return yield* new S.NotFound({ message: "Device authorization is not enabled" });
  }
  const provideStores = <A, E, R>(effect: Effect.Effect<A, E, R>) =>
    effect.pipe(Effect.provideService(DeviceAuthorizationStore, store.value));
  return { service: service.value, provideStores };
});

/** Resolve the username service + store, or fail with 404. */
const resolveUsername = Effect.gen(function* () {
  const service = yield* Effect.serviceOption(UsernameService);
  const store = yield* Effect.serviceOption(UsernameStore);
  if (Option.isNone(service) || Option.isNone(store)) {
    return yield* new S.NotFound({ message: "Username sign-in is not enabled" });
  }
  const provideStores = <A, E, R>(effect: Effect.Effect<A, E, R>) =>
    effect.pipe(Effect.provideService(UsernameStore, store.value));
  return { service: service.value, provideStores };
});

/** Resolve the phone OTP service + stores, or fail with 404. */
const resolvePhoneOtp = Effect.gen(function* () {
  const service = yield* Effect.serviceOption(PhoneOtpService);
  const store = yield* Effect.serviceOption(PhoneOtpStore);
  const userStore = yield* Effect.serviceOption(PhoneOtpUserStore);
  if (Option.isNone(service) || Option.isNone(store) || Option.isNone(userStore)) {
    return yield* new S.NotFound({ message: "Phone OTP is not enabled" });
  }
  const provideStores = <A, E, R>(effect: Effect.Effect<A, E, R>) =>
    effect.pipe(
      Effect.provideService(PhoneOtpStore, store.value),
      Effect.provideService(PhoneOtpUserStore, userStore.value),
    );
  return { service: service.value, provideStores };
});

/** Resolve the anonymous service + store, or fail with 404. */
const resolveAnonymous = Effect.gen(function* () {
  const service = yield* Effect.serviceOption(AnonymousService);
  const store = yield* Effect.serviceOption(AnonymousUserStore);
  if (Option.isNone(service) || Option.isNone(store)) {
    return yield* new S.NotFound({ message: "Anonymous sign-in is not enabled" });
  }
  const provideStores = <A, E, R>(effect: Effect.Effect<A, E, R>) =>
    effect.pipe(Effect.provideService(AnonymousUserStore, store.value));
  return { service: service.value, provideStores };
});

/** Resolve the organization service + store, or fail with 404. */
const resolveOrganization = Effect.gen(function* () {
  const service = yield* Effect.serviceOption(OrganizationService);
  const store = yield* Effect.serviceOption(OrganizationStore);
  if (Option.isNone(service) || Option.isNone(store)) {
    return yield* new S.NotFound({ message: "Organizations are not enabled" });
  }
  const provideStores = <A, E, R>(effect: Effect.Effect<A, E, R>) =>
    effect.pipe(Effect.provideService(OrganizationStore, store.value));
  return { service: service.value, provideStores };
});

/** Resolve the admin service + user store, or fail with 404. */
const resolveAdmin = Effect.gen(function* () {
  const service = yield* Effect.serviceOption(AdminService);
  const store = yield* Effect.serviceOption(AdminUserStore);
  if (Option.isNone(service) || Option.isNone(store)) {
    return yield* new S.NotFound({ message: "Admin is not enabled" });
  }
  const provideStores = <A, E, R>(effect: Effect.Effect<A, E, R>) =>
    effect.pipe(Effect.provideService(AdminUserStore, store.value));
  return { service: service.value, provideStores };
});

/** Resolve the API-key service + store, or fail with 404. */
const resolveApiKey = Effect.gen(function* () {
  const service = yield* Effect.serviceOption(ApiKeyService);
  const store = yield* Effect.serviceOption(ApiKeyStore);
  if (Option.isNone(service) || Option.isNone(store)) {
    return yield* new S.NotFound({ message: "API keys are not enabled" });
  }
  const provideStores = <A, E, R>(effect: Effect.Effect<A, E, R>) =>
    effect.pipe(Effect.provideService(ApiKeyStore, store.value));
  return { service: service.value, provideStores };
});

/** Resolve the JWT service + key store, or fail with 404. */
const resolveJwt = Effect.gen(function* () {
  const service = yield* Effect.serviceOption(JwtService);
  const store = yield* Effect.serviceOption(JwtKeyStore);
  if (Option.isNone(service) || Option.isNone(store)) {
    return yield* new S.NotFound({ message: "JWT is not enabled" });
  }
  const provideStores = <A, E, R>(effect: Effect.Effect<A, E, R>) =>
    effect.pipe(Effect.provideService(JwtKeyStore, store.value));
  return { service: service.value, provideStores };
});

/** Resolve the SSO service + its stores, or fail with 404. */
const resolveSso = Effect.gen(function* () {
  const service = yield* Effect.serviceOption(SsoService);
  const providerStore = yield* Effect.serviceOption(SsoProviderStore);
  const stateStore = yield* Effect.serviceOption(OAuthStateStore);
  const userStore = yield* Effect.serviceOption(OAuthUserStore);
  if (
    Option.isNone(service) ||
    Option.isNone(providerStore) ||
    Option.isNone(stateStore) ||
    Option.isNone(userStore)
  ) {
    return yield* new S.NotFound({ message: "SSO is not enabled" });
  }
  const provideStores = <A, E, R>(effect: Effect.Effect<A, E, R>) =>
    effect.pipe(
      Effect.provideService(SsoProviderStore, providerStore.value),
      Effect.provideService(OAuthStateStore, stateStore.value),
      Effect.provideService(OAuthUserStore, userStore.value),
    );
  return { service: service.value, provideStores };
});

/** Resolve the Google One Tap service + required stores, or fail with 404. */
const resolveGoogleOneTap = Effect.gen(function* () {
  const service = yield* Effect.serviceOption(GoogleOneTapService);
  const userStore = yield* Effect.serviceOption(OAuthUserStore);
  const nonceStore = yield* Effect.serviceOption(GoogleOneTapNonceStore);
  if (Option.isNone(service) || Option.isNone(userStore) || Option.isNone(nonceStore)) {
    return yield* new S.NotFound({ message: "Google One Tap is not enabled" });
  }
  const provideStores = <A, E, R>(effect: Effect.Effect<A, E, R>) =>
    effect.pipe(
      Effect.provideService(OAuthUserStore, userStore.value),
      Effect.provideService(GoogleOneTapNonceStore, nonceStore.value),
    );
  return { service: service.value, provideStores };
});

/**
 * Resolve the OIDC provider service + its stores, or fail with 404. The
 * module signs `id_token`s with the JWT module's keys, so the JWT service +
 * key store (and the core user store, for claims) are required alongside the
 * OIDC stores.
 */
const resolveOidcProvider = Effect.gen(function* () {
  const service = yield* Effect.serviceOption(OidcProviderService);
  const clientStore = yield* Effect.serviceOption(OidcClientStore);
  const codeStore = yield* Effect.serviceOption(OidcCodeStore);
  const tokenStore = yield* Effect.serviceOption(OidcTokenStore);
  const consentStore = yield* Effect.serviceOption(OidcConsentStore);
  const jwtService = yield* Effect.serviceOption(JwtService);
  const jwtKeyStore = yield* Effect.serviceOption(JwtKeyStore);
  const userStore = yield* Effect.serviceOption(UserStore);
  if (
    Option.isNone(service) ||
    Option.isNone(clientStore) ||
    Option.isNone(codeStore) ||
    Option.isNone(tokenStore) ||
    Option.isNone(consentStore) ||
    Option.isNone(jwtService) ||
    Option.isNone(jwtKeyStore) ||
    Option.isNone(userStore)
  ) {
    return yield* new S.NotFound({ message: "OIDC provider is not enabled" });
  }
  const provideStores = <A, E, R>(effect: Effect.Effect<A, E, R>) =>
    effect.pipe(
      Effect.provideService(OidcClientStore, clientStore.value),
      Effect.provideService(OidcCodeStore, codeStore.value),
      Effect.provideService(OidcTokenStore, tokenStore.value),
      Effect.provideService(OidcConsentStore, consentStore.value),
      Effect.provideService(JwtService, jwtService.value),
      Effect.provideService(JwtKeyStore, jwtKeyStore.value),
      Effect.provideService(UserStore, userStore.value),
    );
  return { service: service.value, provideStores };
});

// --- Encoders for the organization / API-key domain types --------------------

const encodeOrganization = (o: Organization): S.OrganizationView => ({
  id: o.id,
  name: o.name,
  slug: o.slug,
  ...(o.logo !== undefined && { logo: o.logo }),
  metadata: o.metadata,
  createdAt: o.createdAt,
});

const encodeMember = (m: Member): S.MemberView => ({
  id: m.id,
  organizationId: m.organizationId,
  userId: m.userId,
  role: m.role,
  createdAt: m.createdAt,
});

const encodeInvitation = (i: Invitation): S.InvitationView => ({
  id: i.id,
  organizationId: i.organizationId,
  email: i.email,
  role: i.role,
  status: i.status,
  inviterId: i.inviterId,
  expiresAt: i.expiresAt,
  createdAt: i.createdAt,
});

const encodeFullOrganization = (f: FullOrganization): S.FullOrganizationView => ({
  organization: encodeOrganization(f.organization),
  members: f.members.map(encodeMember),
});

const encodeSsoProvider = (p: SsoProvider): S.SsoProviderView => ({
  id: p.id,
  issuer: p.issuer,
  domain: p.domain,
  protocol: p.protocol,
  clientId: p.clientId,
  redirectUri: p.redirectUri,
  authorizationEndpoint: p.authorizationEndpoint,
  tokenEndpoint: p.tokenEndpoint,
  ...(p.userInfoEndpoint !== undefined && { userInfoEndpoint: p.userInfoEndpoint }),
  ...(p.jwksEndpoint !== undefined && { jwksEndpoint: p.jwksEndpoint }),
  scopes: p.scopes,
  ...(p.organizationId !== undefined && { organizationId: p.organizationId }),
  createdAt: p.createdAt,
});

const encodeOidcClient = (c: OidcClient): S.OidcClientView => ({
  clientId: c.clientId,
  name: c.name,
  redirectUris: c.redirectUris,
  type: c.type,
  skipConsent: c.skipConsent,
  disabled: c.disabled,
  metadata: c.metadata,
  createdAt: c.createdAt,
  updatedAt: c.updatedAt,
});

const encodeApiKey = (k: ApiKey): S.ApiKeyView => ({
  id: k.id,
  ...(k.name !== undefined && { name: k.name }),
  ...(k.prefix !== undefined && { prefix: k.prefix }),
  start: k.start,
  userId: k.userId,
  enabled: k.enabled,
  ...(k.expiresAt !== undefined && { expiresAt: k.expiresAt }),
  ...(k.lastUsedAt !== undefined && { lastUsedAt: k.lastUsedAt }),
  ...(k.permissions !== undefined && { permissions: k.permissions }),
  metadata: k.metadata,
  ...(k.remaining !== undefined && { remaining: k.remaining }),
  ...(k.rateLimit !== undefined && { rateLimit: k.rateLimit }),
  createdAt: k.createdAt,
  updatedAt: k.updatedAt,
});

/**
 * Log the real error server-side and return a generic 500 body so internal
 * implementation details are never exposed to clients.
 */
const internalServerError = (e: unknown): Effect.Effect<never, S.InternalServerError, never> =>
  Effect.logError("[effect-auth] internal error", e).pipe(
    Effect.flatMap(() =>
      Effect.fail(new S.InternalServerError({ message: "Internal server error" })),
    ),
  );

/** Layer implementing the `auth` group handlers. */
export const authGroupLayer = (config?: CookieConfig, multiSession?: MultiSessionConfig) => {
  const cfg = resolveCookieConfig(config, multiSession);

  return HttpApiBuilder.group(AuthApi, "auth", (handlers) =>
    handlers
      .handle("signUp", ({ payload }) =>
        Effect.gen(function* () {
          const lifecycle = yield* AuthLifecycleService;
          const result = yield* lifecycle.signUp(signUpInput(payload)).pipe(
            Effect.catchTags({
              AuthError: (e) => internalServerError(e),
              EmailInUseError: (e) =>
                Effect.fail(new S.Conflict({ message: e.message, code: e.code })),
              EmailNotVerifiedError: (e) => Effect.fail(new S.BadRequest({ message: e.message })),
              HashingError: (e) => internalServerError(e),
              EmailVerificationError: (e) => internalServerError(e),
              RateLimitError: (e) =>
                Effect.fail(new S.TooManyRequests({ message: e.message, code: e.code })),
              PasswordPolicyError: (e) =>
                resolveMessage(e.code, e.message, e.params).pipe(
                  Effect.flatMap((msg) =>
                    Effect.fail(new S.BadRequest({ message: msg, code: e.code })),
                  ),
                ),
              SignUpDisabledError: (e) =>
                resolveMessage(e.code, e.message).pipe(
                  Effect.flatMap((msg) =>
                    Effect.fail(new S.Forbidden({ message: msg, code: e.code })),
                  ),
                ),
              InvalidInputError: (e) =>
                resolveMessage(e.code, e.message).pipe(
                  Effect.flatMap((msg) =>
                    Effect.fail(new S.BadRequest({ message: msg, code: e.code })),
                  ),
                ),
              AccountLockedError: (e) =>
                resolveMessage(e.code, e.message).pipe(
                  Effect.flatMap((msg) =>
                    Effect.fail(new S.Forbidden({ message: msg, code: e.code })),
                  ),
                ),
              UserBannedError: (e) =>
                resolveMessage(e.code, e.message).pipe(
                  Effect.flatMap((msg) =>
                    Effect.fail(new S.Forbidden({ message: msg, code: e.code })),
                  ),
                ),
              CaptchaError: (e) =>
                resolveMessage(e.code, e.message).pipe(
                  Effect.flatMap((msg) =>
                    Effect.fail(new S.BadRequest({ message: msg, code: e.code })),
                  ),
                ),
              PwnedPasswordError: (e) =>
                resolveMessage(e.code, e.message).pipe(
                  Effect.flatMap((msg) =>
                    Effect.fail(new S.BadRequest({ message: msg, code: e.code })),
                  ),
                ),
            }),
          );
          const body: S.AuthSuccess = {
            user: S.encodeUser(result.user),
            needsEmailVerification: result.needsEmailVerification,
          };
          return yield* withSessionCookie(body, result.session, cfg, "email-password");
        }),
      )
      .handle("signIn", ({ payload }) =>
        Effect.gen(function* () {
          const lifecycle = yield* AuthLifecycleService;
          const result = yield* lifecycle
            .signIn({
              email: payload.email,
              password: payload.password,
              ...(payload.captchaToken !== undefined && { captchaToken: payload.captchaToken }),
              ...(payload.rememberMe !== undefined && { rememberMe: payload.rememberMe }),
            })
            .pipe(
              Effect.catchTags({
                InvalidCredentialsError: (e) =>
                  Effect.fail(new S.Unauthorized({ message: e.message, code: e.code })),
                AuthError: (e) => internalServerError(e),
                HashingError: (e) => internalServerError(e),
                EmailVerificationError: (e) => internalServerError(e),
                RateLimitError: (e) =>
                  Effect.fail(new S.TooManyRequests({ message: e.message, code: e.code })),
                AccountLockedError: (e) =>
                  resolveMessage(e.code, e.message).pipe(
                    Effect.flatMap((msg) =>
                      Effect.fail(new S.Forbidden({ message: msg, code: e.code })),
                    ),
                  ),
                UserBannedError: (e) =>
                  resolveMessage(e.code, e.message).pipe(
                    Effect.flatMap((msg) =>
                      Effect.fail(new S.Forbidden({ message: msg, code: e.code })),
                    ),
                  ),
                CaptchaError: (e) =>
                  resolveMessage(e.code, e.message).pipe(
                    Effect.flatMap((msg) =>
                      Effect.fail(new S.BadRequest({ message: msg, code: e.code })),
                    ),
                  ),
                PwnedPasswordError: (e) =>
                  resolveMessage(e.code, e.message).pipe(
                    Effect.flatMap((msg) =>
                      Effect.fail(new S.BadRequest({ message: msg, code: e.code })),
                    ),
                  ),
              }),
            );
          const body: S.AuthSuccess = {
            user: S.encodeUser(result.user),
            needsEmailVerification: result.needsEmailVerification,
            ...(result.secondFactor !== undefined && { secondFactor: result.secondFactor }),
          };
          return yield* withSessionCookie(
            body,
            result.session,
            cfg,
            "email-password",
            result.rememberMe,
          );
        }),
      )
      .handle("signOut", ({ request }) =>
        Effect.gen(function* () {
          const sessionId = sessionIdFromRequest(request, cfg);
          if (sessionId !== undefined) {
            const sessionManager = yield* SessionManager;
            yield* Effect.ignore(sessionManager.invalidateSession(sessionId));
          }
          let response = yield* HttpServerResponse.setCookie(
            HttpServerResponse.empty({ status: 204 }),
            cfg.name,
            "",
            clearCookieOptions(cfg),
          );
          // Also clear the session-data cache cookie (if in use).
          if (cfg.cache !== undefined) {
            response = yield* HttpServerResponse.setCookie(
              response,
              dataCookieName(cfg),
              "",
              clearCookieOptions(cfg),
            );
          }
          // Multi-session: sign out only the active account; drop it from the
          // device list and keep the others (switch via /multi-session/set-active).
          if (cfg.multiSession !== undefined) {
            const remaining = readDeviceSessionIds(request, cfg).filter((id) => id !== sessionId);
            response = yield* HttpServerResponse.setCookie(
              response,
              multiCookieName(cfg),
              remaining.join("."),
              sessionCookieOptions(cfg, new Date(Date.now() + 30 * 24 * 60 * 60 * 1000)),
            );
          }
          return response;
        }).pipe(Effect.orDie),
      )
      .handle("getSession", ({ request }) =>
        Effect.gen(function* () {
          const { resolved, cacheHit } = yield* resolveSession(request, cfg);
          const body = S.encodeSessionWithUser(resolved);
          // On a store validation (cache miss) refresh the signed cache cookie
          // so subsequent reads within `maxAge` skip the store.
          if (cfg.cache !== undefined && !cacheHit) {
            const cache = cfg.cache;
            const value = encodeSessionCacheCookie(
              resolved,
              cache,
              Date.now(),
              resolved.session.id,
            );
            return yield* HttpServerResponse.json(body).pipe(
              Effect.flatMap((response) =>
                HttpServerResponse.setCookie(
                  response,
                  dataCookieName(cfg),
                  value,
                  dataCookieOptions(cfg, cache),
                ),
              ),
              Effect.orDie,
            );
          }
          return body;
        }),
      )
      .handle("sendVerificationEmail", ({ payload }) =>
        Effect.gen(function* () {
          const store = yield* EmailPasswordStore;
          const verification = yield* EmailVerificationService;
          const email = payload.email.trim().toLowerCase();

          const user = yield* store.getUserByEmail(email).pipe(Effect.catch(internalServerError));

          // Anti-enumeration: succeed uniformly whether or not the user exists
          // (or is already verified).
          if (user !== null && !user.emailVerified) {
            yield* verification.resendVerification(user.id, email).pipe(
              Effect.catchTags({
                AuthError: (e) => internalServerError(e),
                EmailVerificationError: (e) => internalServerError(e),
                RateLimitError: (e) => Effect.fail(new S.TooManyRequests({ message: e.message })),
                AccountLockedError: (e) =>
                  resolveMessage(e.code, e.message).pipe(
                    Effect.flatMap((msg) =>
                      Effect.fail(new S.Forbidden({ message: msg, code: e.code })),
                    ),
                  ),
                UserBannedError: (e) =>
                  resolveMessage(e.code, e.message).pipe(
                    Effect.flatMap((msg) =>
                      Effect.fail(new S.Forbidden({ message: msg, code: e.code })),
                    ),
                  ),
                CaptchaError: (e) =>
                  resolveMessage(e.code, e.message).pipe(
                    Effect.flatMap((msg) =>
                      Effect.fail(new S.BadRequest({ message: msg, code: e.code })),
                    ),
                  ),
                PwnedPasswordError: (e) =>
                  resolveMessage(e.code, e.message).pipe(
                    Effect.flatMap((msg) =>
                      Effect.fail(new S.BadRequest({ message: msg, code: e.code })),
                    ),
                  ),
              }),
            );
          }

          return { status: true };
        }),
      )
      .handle("verifyEmail", ({ payload }) =>
        Effect.gen(function* () {
          const lifecycle = yield* AuthLifecycleService;
          const result = yield* lifecycle.verifyEmail({ token: payload.token }).pipe(
            Effect.catchTags({
              EmailVerificationError: (e) => Effect.fail(new S.BadRequest({ message: e.message })),
              UserNotFoundError: (e) => Effect.fail(new S.BadRequest({ message: e.message })),
              AuthError: (e) => internalServerError(e),
              RateLimitError: (e) => Effect.fail(new S.TooManyRequests({ message: e.message })),
              AccountLockedError: (e) =>
                resolveMessage(e.code, e.message).pipe(
                  Effect.flatMap((msg) =>
                    Effect.fail(new S.Forbidden({ message: msg, code: e.code })),
                  ),
                ),
              UserBannedError: (e) =>
                resolveMessage(e.code, e.message).pipe(
                  Effect.flatMap((msg) =>
                    Effect.fail(new S.Forbidden({ message: msg, code: e.code })),
                  ),
                ),
              CaptchaError: (e) =>
                resolveMessage(e.code, e.message).pipe(
                  Effect.flatMap((msg) =>
                    Effect.fail(new S.BadRequest({ message: msg, code: e.code })),
                  ),
                ),
              PwnedPasswordError: (e) =>
                resolveMessage(e.code, e.message).pipe(
                  Effect.flatMap((msg) =>
                    Effect.fail(new S.BadRequest({ message: msg, code: e.code })),
                  ),
                ),
            }),
          );
          const body: S.AuthSuccess = {
            user: S.encodeUser(result.user),
            needsEmailVerification: result.needsEmailVerification,
          };
          return yield* withSessionCookie(body, result.session, cfg, "email-password");
        }),
      )
      .handle("passwordResetRequest", ({ payload }) =>
        Effect.gen(function* () {
          const passwordReset = yield* PasswordResetService;
          yield* passwordReset.requestPasswordReset(payload.email).pipe(
            Effect.catchTags({
              AuthError: (e) => internalServerError(e),
              PasswordResetError: (e) => internalServerError(e),
              RateLimitError: (e) => Effect.fail(new S.TooManyRequests({ message: e.message })),
              AccountLockedError: (e) =>
                resolveMessage(e.code, e.message).pipe(
                  Effect.flatMap((msg) =>
                    Effect.fail(new S.Forbidden({ message: msg, code: e.code })),
                  ),
                ),
              UserBannedError: (e) =>
                resolveMessage(e.code, e.message).pipe(
                  Effect.flatMap((msg) =>
                    Effect.fail(new S.Forbidden({ message: msg, code: e.code })),
                  ),
                ),
              CaptchaError: (e) =>
                resolveMessage(e.code, e.message).pipe(
                  Effect.flatMap((msg) =>
                    Effect.fail(new S.BadRequest({ message: msg, code: e.code })),
                  ),
                ),
              PwnedPasswordError: (e) =>
                resolveMessage(e.code, e.message).pipe(
                  Effect.flatMap((msg) =>
                    Effect.fail(new S.BadRequest({ message: msg, code: e.code })),
                  ),
                ),
            }),
          );
          return { status: true };
        }),
      )
      .handle("passwordResetConfirm", ({ payload }) =>
        Effect.gen(function* () {
          const passwordReset = yield* PasswordResetService;
          yield* passwordReset.resetPassword(payload.token, payload.newPassword).pipe(
            Effect.catchTags({
              PasswordResetError: (e) => Effect.fail(new S.BadRequest({ message: e.message })),
              AuthError: (e) => internalServerError(e),
              HashingError: (e) => internalServerError(e),
              RateLimitError: (e) => Effect.fail(new S.TooManyRequests({ message: e.message })),
              AccountLockedError: (e) =>
                resolveMessage(e.code, e.message).pipe(
                  Effect.flatMap((msg) =>
                    Effect.fail(new S.Forbidden({ message: msg, code: e.code })),
                  ),
                ),
              UserBannedError: (e) =>
                resolveMessage(e.code, e.message).pipe(
                  Effect.flatMap((msg) =>
                    Effect.fail(new S.Forbidden({ message: msg, code: e.code })),
                  ),
                ),
              CaptchaError: (e) =>
                resolveMessage(e.code, e.message).pipe(
                  Effect.flatMap((msg) =>
                    Effect.fail(new S.BadRequest({ message: msg, code: e.code })),
                  ),
                ),
              PwnedPasswordError: (e) =>
                resolveMessage(e.code, e.message).pipe(
                  Effect.flatMap((msg) =>
                    Effect.fail(new S.BadRequest({ message: msg, code: e.code })),
                  ),
                ),
            }),
          );
          return { status: true };
        }),
      )
      .handle("changePassword", ({ payload, request }) =>
        Effect.gen(function* () {
          const resolved = yield* requireSession(request, cfg);
          const emailPassword = yield* makeEmailPasswordService();
          yield* emailPassword
            .changePassword({
              userId: resolved.user.id,
              currentPassword: payload.currentPassword,
              newPassword: payload.newPassword,
              ...(payload.revokeOtherSessions !== undefined && {
                revokeOtherSessions: payload.revokeOtherSessions,
              }),
              currentSessionId: resolved.session.id,
            })
            .pipe(
              Effect.catchTags({
                InvalidCredentialsError: (e) =>
                  Effect.fail(new S.BadRequest({ message: e.message, code: e.code })),
                AuthError: (e) => internalServerError(e),
                HashingError: (e) => internalServerError(e),
                PasswordPolicyError: (e) =>
                  resolveMessage(e.code, e.message, e.params).pipe(
                    Effect.flatMap((msg) =>
                      Effect.fail(new S.BadRequest({ message: msg, code: e.code })),
                    ),
                  ),
              }),
            );
        }),
      )
      .handle("updateUser", ({ payload, request }) =>
        Effect.gen(function* () {
          const resolved = yield* requireSession(request, cfg);
          const userService = yield* UserService;
          const updated = yield* userService
            .updateUser(resolved.user.id, {
              ...(payload.name !== undefined && { name: payload.name }),
              ...(payload.image !== undefined && { image: payload.image }),
            })
            .pipe(
              Effect.catchTags({
                UserNotFoundError: () =>
                  Effect.fail(new S.Unauthorized({ message: "Not authenticated" })),
                AuthError: (e) => internalServerError(e),
              }),
            );
          return S.encodeUser(updated);
        }),
      )
      .handle("changeEmailRequest", ({ payload, request }) =>
        Effect.gen(function* () {
          const resolved = yield* requireSession(request, cfg);
          const account = yield* resolveAccountManagement;
          yield* account
            .provideStores(account.service.requestEmailChange(resolved.user.id, payload.newEmail))
            .pipe(
              Effect.catchTags({
                // Anti-enumeration: never reveal whether the target email exists.
                EmailInUseError: () => Effect.void,
                UserNotFoundError: () =>
                  Effect.fail(new S.Unauthorized({ message: "Not authenticated" })),
                AuthError: (e) => internalServerError(e),
              }),
            );
          return { status: true };
        }),
      )
      .handle("changeEmailConfirm", ({ payload, request: _r }) =>
        Effect.gen(function* () {
          const account = yield* resolveAccountManagement;
          yield* account.provideStores(account.service.confirmEmailChange(payload.token)).pipe(
            Effect.catchTags({
              AccountTokenError: (e) => Effect.fail(new S.BadRequest({ message: e.message })),
              UserNotFoundError: (e) => Effect.fail(new S.BadRequest({ message: e.message })),
              AuthError: (e) => internalServerError(e),
            }),
          );
          return yield* HttpServerResponse.json({ status: true }).pipe(
            Effect.flatMap((response) =>
              cfg.cache !== undefined
                ? HttpServerResponse.setCookie(
                    response,
                    dataCookieName(cfg),
                    "",
                    clearCookieOptions(cfg),
                  )
                : Effect.succeed(response),
            ),
            Effect.orDie,
          );
        }),
      )
      .handle("deleteUserRequest", ({ request }) =>
        Effect.gen(function* () {
          const resolved = yield* requireSession(request, cfg);
          const account = yield* resolveAccountManagement;
          yield* account
            .provideStores(account.service.requestAccountDeletion(resolved.user.id))
            .pipe(
              Effect.catchTags({
                UserNotFoundError: () =>
                  Effect.fail(new S.Unauthorized({ message: "Not authenticated" })),
                AuthError: (e) => internalServerError(e),
              }),
            );
          return { status: true };
        }),
      )
      .handle("deleteUserConfirm", ({ payload, request: _r }) =>
        Effect.gen(function* () {
          const account = yield* resolveAccountManagement;
          yield* account.provideStores(account.service.confirmAccountDeletion(payload.token)).pipe(
            Effect.catchTags({
              AccountTokenError: (e) => Effect.fail(new S.BadRequest({ message: e.message })),
              UserNotFoundError: (e) => Effect.fail(new S.BadRequest({ message: e.message })),
              AuthError: (e) => internalServerError(e),
            }),
          );
          return yield* HttpServerResponse.json({ status: true }).pipe(
            Effect.flatMap((response) =>
              cfg.cache !== undefined
                ? HttpServerResponse.setCookie(
                    response,
                    dataCookieName(cfg),
                    "",
                    clearCookieOptions(cfg),
                  )
                : Effect.succeed(response),
            ),
            Effect.orDie,
          );
        }),
      )
      .handle("listSessions", ({ request }) =>
        Effect.gen(function* () {
          const resolved = yield* requireSession(request, cfg);
          const sessionManager = yield* SessionManager;
          const sessions = yield* sessionManager
            .listSessions(resolved.user.id)
            .pipe(Effect.catch(internalServerError));
          return sessions.map(S.encodeSession);
        }),
      )
      .handle("revokeSession", ({ params, request }) =>
        Effect.gen(function* () {
          const resolved = yield* requireSession(request, cfg);
          const sessionManager = yield* SessionManager;

          const sessions = yield* sessionManager
            .listSessions(resolved.user.id)
            .pipe(Effect.catch(internalServerError));

          // Only the owner may revoke a session, and only their own sessions.
          // params.sessionId is the raw token from the URL; sessions in the list
          // have hash ids (stored by hash), so compare against the hash.
          const targetHash = hashToken(params.sessionId);
          const target = sessions.find((session) => session.id === targetHash);
          if (target === undefined) {
            return yield* new S.BadRequest({ message: "Session not found" });
          }

          yield* sessionManager
            .invalidateSession(params.sessionId)
            .pipe(Effect.catch(internalServerError));
        }),
      )
      .handle("revokeOtherSessions", ({ request }) =>
        Effect.gen(function* () {
          const resolved = yield* requireSession(request, cfg);
          const sessionManager = yield* SessionManager;
          yield* sessionManager
            .revokeOtherSessions(resolved.user.id, resolved.session.id)
            .pipe(Effect.catch(internalServerError));
        }),
      )
      .handle("magicLinkSend", ({ payload }) =>
        Effect.gen(function* () {
          const magicLink = yield* resolveMagicLink;
          // Anti-enumeration: the service succeeds silently for unknown
          // accounts; only store/delivery failures surface (as 500).
          yield* magicLink.provideStores(magicLink.service.send(payload.email)).pipe(
            Effect.catchTags({
              AuthError: (e) => internalServerError(e),
              MagicLinkError: (e) => internalServerError(e),
              ResendTooSoonError: (e) =>
                Effect.fail(new S.TooManyRequests({ message: e.message, code: e.code })),
            }),
          );
          return { status: true };
        }),
      )
      .handle("magicLinkVerify", ({ payload }) =>
        Effect.gen(function* () {
          const magicLink = yield* resolveMagicLink;
          const result = yield* magicLink
            .provideStores(magicLink.service.verify(payload.token))
            .pipe(
              Effect.catchTags({
                MagicLinkError: (e) => Effect.fail(new S.BadRequest({ message: e.message })),
                AuthError: (e) => internalServerError(e),
                RateLimitError: (e) => Effect.fail(new S.TooManyRequests({ message: e.message })),
                AccountLockedError: (e) =>
                  resolveMessage(e.code, e.message).pipe(
                    Effect.flatMap((msg) =>
                      Effect.fail(new S.Forbidden({ message: msg, code: e.code })),
                    ),
                  ),
                UserBannedError: (e) =>
                  resolveMessage(e.code, e.message).pipe(
                    Effect.flatMap((msg) =>
                      Effect.fail(new S.Forbidden({ message: msg, code: e.code })),
                    ),
                  ),
                CaptchaError: (e) =>
                  resolveMessage(e.code, e.message).pipe(
                    Effect.flatMap((msg) =>
                      Effect.fail(new S.BadRequest({ message: msg, code: e.code })),
                    ),
                  ),
                PwnedPasswordError: (e) =>
                  resolveMessage(e.code, e.message).pipe(
                    Effect.flatMap((msg) =>
                      Effect.fail(new S.BadRequest({ message: msg, code: e.code })),
                    ),
                  ),
              }),
            );
          const body: S.AuthSuccess = {
            user: S.encodeUser(result.user),
            needsEmailVerification: false,
          };
          return yield* withSessionCookie(body, result.session, cfg, "magic-link");
        }),
      )
      .handle("emailOtpSend", ({ payload }) =>
        Effect.gen(function* () {
          const emailOtp = yield* resolveEmailOtp;
          // Anti-enumeration: the service succeeds silently for unknown
          // accounts; only store/delivery failures surface (as 500).
          yield* emailOtp.provideStores(emailOtp.service.send(payload.email, payload.purpose)).pipe(
            Effect.catchTags({
              AuthError: (e) => internalServerError(e),
              EmailOtpError: (e) => internalServerError(e),
              ResendTooSoonError: (e) =>
                Effect.fail(new S.TooManyRequests({ message: e.message, code: e.code })),
            }),
          );
          return { status: true };
        }),
      )
      .handle("signInEmailOtp", ({ payload }) =>
        Effect.gen(function* () {
          const emailOtp = yield* resolveEmailOtp;
          const result = yield* emailOtp
            .provideStores(emailOtp.service.signIn(payload.email, payload.otp))
            .pipe(
              Effect.catchTags({
                EmailOtpError: (e) => Effect.fail(new S.BadRequest({ message: e.message })),
                AuthError: (e) => internalServerError(e),
                RateLimitError: (e) => Effect.fail(new S.TooManyRequests({ message: e.message })),
                AccountLockedError: (e) =>
                  resolveMessage(e.code, e.message).pipe(
                    Effect.flatMap((msg) =>
                      Effect.fail(new S.Forbidden({ message: msg, code: e.code })),
                    ),
                  ),
                UserBannedError: (e) =>
                  resolveMessage(e.code, e.message).pipe(
                    Effect.flatMap((msg) =>
                      Effect.fail(new S.Forbidden({ message: msg, code: e.code })),
                    ),
                  ),
                CaptchaError: (e) =>
                  resolveMessage(e.code, e.message).pipe(
                    Effect.flatMap((msg) =>
                      Effect.fail(new S.BadRequest({ message: msg, code: e.code })),
                    ),
                  ),
                PwnedPasswordError: (e) =>
                  resolveMessage(e.code, e.message).pipe(
                    Effect.flatMap((msg) =>
                      Effect.fail(new S.BadRequest({ message: msg, code: e.code })),
                    ),
                  ),
              }),
            );
          const body: S.AuthSuccess = {
            user: S.encodeUser(result.user),
            needsEmailVerification: false,
          };
          return yield* withSessionCookie(body, result.session, cfg, "email-otp");
        }),
      )
      .handle("signInAnonymous", () =>
        Effect.gen(function* () {
          const anonymous = yield* resolveAnonymous;
          const result = yield* anonymous.provideStores(anonymous.service.signInAnonymous()).pipe(
            Effect.catchTags({
              AuthError: (e) => internalServerError(e),
              RateLimitError: (e) => Effect.fail(new S.TooManyRequests({ message: e.message })),
              AccountLockedError: (e) =>
                resolveMessage(e.code, e.message).pipe(
                  Effect.flatMap((msg) =>
                    Effect.fail(new S.Forbidden({ message: msg, code: e.code })),
                  ),
                ),
              UserBannedError: (e) =>
                resolveMessage(e.code, e.message).pipe(
                  Effect.flatMap((msg) =>
                    Effect.fail(new S.Forbidden({ message: msg, code: e.code })),
                  ),
                ),
              CaptchaError: (e) =>
                resolveMessage(e.code, e.message).pipe(
                  Effect.flatMap((msg) =>
                    Effect.fail(new S.BadRequest({ message: msg, code: e.code })),
                  ),
                ),
              PwnedPasswordError: (e) =>
                resolveMessage(e.code, e.message).pipe(
                  Effect.flatMap((msg) =>
                    Effect.fail(new S.BadRequest({ message: msg, code: e.code })),
                  ),
                ),
            }),
          );
          const body: S.AuthSuccess = {
            user: S.encodeUser(result.user),
            needsEmailVerification: false,
          };
          return yield* withSessionCookie(body, result.session, cfg, "anonymous");
        }),
      )
      .handle("signInUsername", ({ payload }) =>
        Effect.gen(function* () {
          const username = yield* resolveUsername;
          const result = yield* username
            .provideStores(
              username.service.signIn({
                username: payload.username,
                password: payload.password,
                ...(payload.rememberMe !== undefined && { rememberMe: payload.rememberMe }),
              }),
            )
            .pipe(
              Effect.catchTags({
                UsernameError: (e) => Effect.fail(new S.Unauthorized({ message: e.message })),
                InvalidCredentialsError: (e) =>
                  Effect.fail(new S.Unauthorized({ message: e.message })),
                EmailNotVerifiedError: (e) =>
                  Effect.fail(new S.Unauthorized({ message: e.message })),
                HashingError: (e) => internalServerError(e),
                AuthError: (e) => internalServerError(e),
                RateLimitError: (e) => Effect.fail(new S.TooManyRequests({ message: e.message })),
                AccountLockedError: (e) =>
                  resolveMessage(e.code, e.message).pipe(
                    Effect.flatMap((msg) =>
                      Effect.fail(new S.Forbidden({ message: msg, code: e.code })),
                    ),
                  ),
                UserBannedError: (e) =>
                  resolveMessage(e.code, e.message).pipe(
                    Effect.flatMap((msg) =>
                      Effect.fail(new S.Forbidden({ message: msg, code: e.code })),
                    ),
                  ),
                CaptchaError: (e) =>
                  resolveMessage(e.code, e.message).pipe(
                    Effect.flatMap((msg) =>
                      Effect.fail(new S.BadRequest({ message: msg, code: e.code })),
                    ),
                  ),
                PwnedPasswordError: (e) =>
                  resolveMessage(e.code, e.message).pipe(
                    Effect.flatMap((msg) =>
                      Effect.fail(new S.BadRequest({ message: msg, code: e.code })),
                    ),
                  ),
              }),
            );
          const body: S.AuthSuccess = {
            user: S.encodeUser(result.user),
            needsEmailVerification: false,
            ...(result.secondFactor !== undefined && { secondFactor: result.secondFactor }),
          };
          return yield* withSessionCookie(body, result.session, cfg, "username", result.rememberMe);
        }),
      )
      .handle("multiSessionList", ({ request }) =>
        Effect.gen(function* () {
          if (cfg.multiSession === undefined) {
            return yield* new S.NotFound({ message: "Multi-session is not enabled" });
          }
          const sessionManager = yield* SessionManager;
          const active = sessionIdFromRequest(request, cfg);
          const ids = new Set(readDeviceSessionIds(request, cfg));
          if (active !== undefined) ids.add(active);

          const views: S.SessionWithUserView[] = [];
          for (const id of ids) {
            const resolved = yield* sessionManager
              .validateSession(id)
              .pipe(Effect.catch(() => Effect.succeed(null)));
            if (resolved !== null) views.push(S.encodeSessionWithUser(resolved));
          }
          return views;
        }),
      )
      .handle("multiSessionSetActive", ({ payload, request }) =>
        Effect.gen(function* () {
          if (cfg.multiSession === undefined) {
            return yield* new S.NotFound({ message: "Multi-session is not enabled" });
          }
          if (!readDeviceSessionIds(request, cfg).includes(payload.sessionId)) {
            return yield* new S.BadRequest({ message: "Session is not on this device" });
          }
          const sessionManager = yield* SessionManager;
          const resolved = yield* sessionManager
            .validateSession(payload.sessionId)
            .pipe(
              Effect.mapError(() => new S.BadRequest({ message: "Invalid or expired session" })),
            );
          return yield* HttpServerResponse.json({ status: true }).pipe(
            Effect.flatMap((response) =>
              HttpServerResponse.setCookie(
                response,
                cfg.name,
                resolved.session.id,
                sessionCookieOptions(cfg, resolved.session.expiresAt),
              ),
            ),
            Effect.flatMap((response) =>
              cfg.cache !== undefined
                ? HttpServerResponse.setCookie(
                    response,
                    dataCookieName(cfg),
                    "",
                    clearCookieOptions(cfg),
                  )
                : Effect.succeed(response),
            ),
            Effect.orDie,
          );
        }),
      )
      .handle("multiSessionRevoke", ({ payload, request }) =>
        Effect.gen(function* () {
          if (cfg.multiSession === undefined) {
            return yield* new S.NotFound({ message: "Multi-session is not enabled" });
          }
          const sessionManager = yield* SessionManager;
          yield* sessionManager
            .invalidateSession(payload.sessionId)
            .pipe(Effect.catch(internalServerError));

          const remaining = readDeviceSessionIds(request, cfg).filter(
            (id) => id !== payload.sessionId,
          );
          const farFuture = new Date(Date.now() + 30 * 24 * 60 * 60 * 1000);
          const wasActive = sessionIdFromRequest(request, cfg) === payload.sessionId;
          return yield* Effect.gen(function* () {
            let response = yield* HttpServerResponse.json({ status: true });
            response = yield* HttpServerResponse.setCookie(
              response,
              multiCookieName(cfg),
              remaining.join("."),
              sessionCookieOptions(cfg, farFuture),
            );
            if (wasActive) {
              response = yield* HttpServerResponse.setCookie(
                response,
                cfg.name,
                "",
                clearCookieOptions(cfg),
              );
              if (cfg.cache !== undefined) {
                response = yield* HttpServerResponse.setCookie(
                  response,
                  dataCookieName(cfg),
                  "",
                  clearCookieOptions(cfg),
                );
              }
            }
            return response;
          }).pipe(Effect.orDie);
        }),
      )
      .handle("deviceCode", ({ payload }) =>
        Effect.gen(function* () {
          const device = yield* resolveDevice;
          return yield* device
            .provideStores(
              device.service.begin({
                ...(payload.clientId !== undefined && { clientId: payload.clientId }),
                ...(payload.scopes !== undefined && { scopes: payload.scopes }),
              }),
            )
            .pipe(
              Effect.catchTags({
                AuthError: (e) => internalServerError(e),
              }),
            );
        }),
      )
      .handle("deviceToken", ({ payload }) =>
        Effect.gen(function* () {
          const device = yield* resolveDevice;
          const result = yield* device.provideStores(device.service.poll(payload.deviceCode)).pipe(
            Effect.catchTags({
              // RFC 8628 poll errors -> 400 with the error code as message.
              DevicePollError: (e) => Effect.fail(new S.BadRequest({ message: e.error })),
              SessionNotFoundError: (e) => internalServerError(e),
              SessionExpiredError: (e) => internalServerError(e),
              UserNotFoundError: (e) => internalServerError(e),
              AuthError: (e) => internalServerError(e),
              RateLimitError: (e) => Effect.fail(new S.TooManyRequests({ message: e.message })),
              AccountLockedError: (e) =>
                resolveMessage(e.code, e.message).pipe(
                  Effect.flatMap((msg) =>
                    Effect.fail(new S.Forbidden({ message: msg, code: e.code })),
                  ),
                ),
              UserBannedError: (e) =>
                resolveMessage(e.code, e.message).pipe(
                  Effect.flatMap((msg) =>
                    Effect.fail(new S.Forbidden({ message: msg, code: e.code })),
                  ),
                ),
              CaptchaError: (e) =>
                resolveMessage(e.code, e.message).pipe(
                  Effect.flatMap((msg) =>
                    Effect.fail(new S.BadRequest({ message: msg, code: e.code })),
                  ),
                ),
              PwnedPasswordError: (e) =>
                resolveMessage(e.code, e.message).pipe(
                  Effect.flatMap((msg) =>
                    Effect.fail(new S.BadRequest({ message: msg, code: e.code })),
                  ),
                ),
            }),
          );
          const body: S.AuthSuccess = {
            user: S.encodeUser(result.user),
            needsEmailVerification: false,
          };
          return yield* withSessionCookie(body, result.session, cfg, "device");
        }),
      )
      .handle("deviceApprove", ({ payload, request }) =>
        Effect.gen(function* () {
          const resolved = yield* requireSession(request, cfg);
          const device = yield* resolveDevice;
          yield* device
            .provideStores(device.service.approve(payload.userCode, resolved.user.id))
            .pipe(
              Effect.catchTags({
                DeviceCodeError: (e) => Effect.fail(new S.BadRequest({ message: e.message })),
                AuthError: (e) => internalServerError(e),
              }),
            );
          return { status: true };
        }),
      )
      .handle("deviceDeny", ({ payload }) =>
        Effect.gen(function* () {
          const device = yield* resolveDevice;
          yield* device.provideStores(device.service.deny(payload.userCode)).pipe(
            Effect.catchTags({
              DeviceCodeError: (e) => Effect.fail(new S.BadRequest({ message: e.message })),
              AuthError: (e) => internalServerError(e),
            }),
          );
          return { status: true };
        }),
      )
      .handle("phoneOtpSend", ({ payload }) =>
        Effect.gen(function* () {
          const phoneOtp = yield* resolvePhoneOtp;
          yield* phoneOtp
            .provideStores(phoneOtp.service.send(payload.phoneNumber, payload.purpose))
            .pipe(
              Effect.catchTags({
                // Anti-enumeration: send never signals whether the number exists.
                PhoneOtpError: (e) => internalServerError(e),
                AuthError: (e) => internalServerError(e),
                ResendTooSoonError: (e) =>
                  Effect.fail(new S.TooManyRequests({ message: e.message, code: e.code })),
              }),
            );
          return { status: true };
        }),
      )
      .handle("signInPhoneOtp", ({ payload }) =>
        Effect.gen(function* () {
          const phoneOtp = yield* resolvePhoneOtp;
          const result = yield* phoneOtp
            .provideStores(phoneOtp.service.signIn(payload.phoneNumber, payload.otp))
            .pipe(
              Effect.catchTags({
                PhoneOtpError: (e) => Effect.fail(new S.BadRequest({ message: e.message })),
                AuthError: (e) => internalServerError(e),
                RateLimitError: (e) => Effect.fail(new S.TooManyRequests({ message: e.message })),
                AccountLockedError: (e) =>
                  resolveMessage(e.code, e.message).pipe(
                    Effect.flatMap((msg) =>
                      Effect.fail(new S.Forbidden({ message: msg, code: e.code })),
                    ),
                  ),
                UserBannedError: (e) =>
                  resolveMessage(e.code, e.message).pipe(
                    Effect.flatMap((msg) =>
                      Effect.fail(new S.Forbidden({ message: msg, code: e.code })),
                    ),
                  ),
                CaptchaError: (e) =>
                  resolveMessage(e.code, e.message).pipe(
                    Effect.flatMap((msg) =>
                      Effect.fail(new S.BadRequest({ message: msg, code: e.code })),
                    ),
                  ),
                PwnedPasswordError: (e) =>
                  resolveMessage(e.code, e.message).pipe(
                    Effect.flatMap((msg) =>
                      Effect.fail(new S.BadRequest({ message: msg, code: e.code })),
                    ),
                  ),
              }),
            );
          const body: S.AuthSuccess = {
            user: S.encodeUser(result.user),
            needsEmailVerification: false,
          };
          return yield* withSessionCookie(body, result.session, cfg, "phone-otp");
        }),
      )
      .handle("twoFactorEnable", ({ payload, request }) =>
        Effect.gen(function* () {
          const resolved = yield* requireSession(request, cfg);
          const twoFactor = yield* resolveTwoFactor;
          // `enable` labels the otpauth:// URI with the user's email via the
          // core UserStore, which is not part of `AuthServices` - resolve it
          // optionally alongside the feature.
          const userStore = yield* Effect.serviceOption(UserStore);
          if (Option.isNone(userStore)) {
            return yield* new S.NotFound({ message: "Two-factor authentication is not enabled" });
          }
          return yield* twoFactor
            .provideStores(twoFactor.service.enable(resolved.user.id, payload.password))
            .pipe(
              Effect.provideService(UserStore, userStore.value),
              Effect.catchTags({
                InvalidCredentialsError: (e) =>
                  Effect.fail(new S.BadRequest({ message: e.message })),
                TwoFactorError: (e) => internalServerError(e),
                UserNotFoundError: (e) => internalServerError(e),
                HashingError: (e) => internalServerError(e),
                AuthError: (e) => internalServerError(e),
              }),
            );
        }),
      )
      .handle("twoFactorConfirm", ({ payload, request }) =>
        Effect.gen(function* () {
          const resolved = yield* requireSession(request, cfg);
          const twoFactor = yield* resolveTwoFactor;
          yield* twoFactor
            .provideStores(twoFactor.service.confirmEnable(resolved.user.id, payload.code))
            .pipe(
              Effect.catchTags({
                TwoFactorError: (e) => Effect.fail(new S.BadRequest({ message: e.message })),
                HashingError: (e) => internalServerError(e),
                AuthError: (e) => internalServerError(e),
              }),
            );
          return { status: true };
        }),
      )
      .handle("twoFactorDisable", ({ payload, request }) =>
        Effect.gen(function* () {
          const resolved = yield* requireSession(request, cfg);
          const twoFactor = yield* resolveTwoFactor;
          yield* twoFactor
            .provideStores(twoFactor.service.disable(resolved.user.id, payload.password))
            .pipe(
              Effect.catchTags({
                InvalidCredentialsError: (e) =>
                  Effect.fail(new S.BadRequest({ message: e.message })),
                HashingError: (e) => internalServerError(e),
                AuthError: (e) => internalServerError(e),
              }),
            );
          return { status: true };
        }),
      )
      .handle("twoFactorRegenerateBackupCodes", ({ payload, request }) =>
        Effect.gen(function* () {
          const resolved = yield* requireSession(request, cfg);
          const twoFactor = yield* resolveTwoFactor;
          const backupCodes = yield* twoFactor
            .provideStores(
              twoFactor.service.regenerateBackupCodes(resolved.user.id, payload.password),
            )
            .pipe(
              Effect.catchTags({
                TwoFactorError: (e) => Effect.fail(new S.BadRequest({ message: e.message })),
                InvalidCredentialsError: (e) =>
                  Effect.fail(new S.BadRequest({ message: e.message })),
                HashingError: (e) => internalServerError(e),
                AuthError: (e) => internalServerError(e),
              }),
            );
          return { backupCodes };
        }),
      )
      .handle("twoFactorVerifyTotp", ({ payload }) =>
        Effect.gen(function* () {
          const twoFactor = yield* resolveTwoFactor;
          const result = yield* twoFactor
            .provideStores(twoFactor.service.verifyTotp(payload.token, payload.code))
            .pipe(
              Effect.catchTags({
                TwoFactorError: (e) => Effect.fail(new S.Unauthorized({ message: e.message })),
                HashingError: (e) => internalServerError(e),
                AuthError: (e) => internalServerError(e),
                RateLimitError: (e) => Effect.fail(new S.TooManyRequests({ message: e.message })),
                AccountLockedError: (e) =>
                  resolveMessage(e.code, e.message).pipe(
                    Effect.flatMap((msg) =>
                      Effect.fail(new S.Forbidden({ message: msg, code: e.code })),
                    ),
                  ),
                UserBannedError: (e) =>
                  resolveMessage(e.code, e.message).pipe(
                    Effect.flatMap((msg) =>
                      Effect.fail(new S.Forbidden({ message: msg, code: e.code })),
                    ),
                  ),
                CaptchaError: (e) =>
                  resolveMessage(e.code, e.message).pipe(
                    Effect.flatMap((msg) =>
                      Effect.fail(new S.BadRequest({ message: msg, code: e.code })),
                    ),
                  ),
                PwnedPasswordError: (e) =>
                  resolveMessage(e.code, e.message).pipe(
                    Effect.flatMap((msg) =>
                      Effect.fail(new S.BadRequest({ message: msg, code: e.code })),
                    ),
                  ),
              }),
            );
          return yield* secondFactorSuccess(result, cfg, "two-factor");
        }),
      )
      .handle("twoFactorVerifyBackupCode", ({ payload }) =>
        Effect.gen(function* () {
          const twoFactor = yield* resolveTwoFactor;
          const result = yield* twoFactor
            .provideStores(twoFactor.service.verifyBackupCode(payload.token, payload.code))
            .pipe(
              Effect.catchTags({
                TwoFactorError: (e) => Effect.fail(new S.Unauthorized({ message: e.message })),
                AuthError: (e) => internalServerError(e),
                RateLimitError: (e) => Effect.fail(new S.TooManyRequests({ message: e.message })),
                AccountLockedError: (e) =>
                  resolveMessage(e.code, e.message).pipe(
                    Effect.flatMap((msg) =>
                      Effect.fail(new S.Forbidden({ message: msg, code: e.code })),
                    ),
                  ),
                UserBannedError: (e) =>
                  resolveMessage(e.code, e.message).pipe(
                    Effect.flatMap((msg) =>
                      Effect.fail(new S.Forbidden({ message: msg, code: e.code })),
                    ),
                  ),
                CaptchaError: (e) =>
                  resolveMessage(e.code, e.message).pipe(
                    Effect.flatMap((msg) =>
                      Effect.fail(new S.BadRequest({ message: msg, code: e.code })),
                    ),
                  ),
                PwnedPasswordError: (e) =>
                  resolveMessage(e.code, e.message).pipe(
                    Effect.flatMap((msg) =>
                      Effect.fail(new S.BadRequest({ message: msg, code: e.code })),
                    ),
                  ),
              }),
            );
          return yield* secondFactorSuccess(result, cfg, "two-factor");
        }),
      )
      // --- Organization -----------------------------------------------------
      .handle("orgCreate", ({ payload, request }) =>
        Effect.gen(function* () {
          const resolved = yield* requireSession(request, cfg);
          const org = yield* resolveOrganization;
          const created = yield* org
            .provideStores(
              org.service.createOrganization(resolved.user.id, {
                name: payload.name,
                slug: payload.slug,
                ...(payload.logo !== undefined && { logo: payload.logo }),
                ...(payload.metadata !== undefined && { metadata: payload.metadata }),
              }),
            )
            .pipe(
              Effect.catchTags({
                OrganizationError: (e) => Effect.fail(new S.BadRequest({ message: e.message })),
                AuthError: (e) => internalServerError(e),
              }),
            );
          return encodeOrganization(created);
        }),
      )
      .handle("orgList", ({ request }) =>
        Effect.gen(function* () {
          const resolved = yield* requireSession(request, cfg);
          const org = yield* resolveOrganization;
          const orgs = yield* org
            .provideStores(org.service.listOrganizations(resolved.user.id))
            .pipe(
              Effect.catchTags({
                AuthError: (e) => internalServerError(e),
              }),
            );
          return orgs.map(encodeOrganization);
        }),
      )
      .handle("orgGet", ({ params, request }) =>
        Effect.gen(function* () {
          yield* requireSession(request, cfg);
          const org = yield* resolveOrganization;
          const full = yield* org
            .provideStores(org.service.getFullOrganization(params.organizationId))
            .pipe(
              Effect.catchTags({
                OrganizationError: (e) => Effect.fail(new S.BadRequest({ message: e.message })),
                AuthError: (e) => internalServerError(e),
              }),
            );
          return encodeFullOrganization(full);
        }),
      )
      .handle("orgUpdate", ({ params, payload, request }) =>
        Effect.gen(function* () {
          const resolved = yield* requireSession(request, cfg);
          const org = yield* resolveOrganization;
          const updated = yield* org
            .provideStores(
              org.service.updateOrganization(resolved.user.id, params.organizationId, {
                ...(payload.name !== undefined && { name: payload.name }),
                ...(payload.slug !== undefined && { slug: payload.slug }),
                ...(payload.logo !== undefined && { logo: payload.logo }),
                ...(payload.metadata !== undefined && { metadata: payload.metadata }),
              }),
            )
            .pipe(
              Effect.catchTags({
                OrganizationError: (e) => Effect.fail(new S.Forbidden({ message: e.message })),
                AuthError: (e) => internalServerError(e),
              }),
            );
          return encodeOrganization(updated);
        }),
      )
      .handle("orgDelete", ({ params, request }) =>
        Effect.gen(function* () {
          const resolved = yield* requireSession(request, cfg);
          const org = yield* resolveOrganization;
          yield* org
            .provideStores(org.service.deleteOrganization(resolved.user.id, params.organizationId))
            .pipe(
              Effect.catchTags({
                OrganizationError: (e) => Effect.fail(new S.Forbidden({ message: e.message })),
                AuthError: (e) => internalServerError(e),
              }),
            );
        }),
      )
      .handle("orgSetActive", ({ payload, request }) =>
        Effect.gen(function* () {
          yield* resolveOrganization; // 404 when organizations are not enabled
          const resolved = yield* requireSession(request, cfg);
          const sessionManager = yield* SessionManager;
          yield* sessionManager
            .setSessionAttributes(resolved.session.id, {
              activeOrganizationId: payload.organizationId,
            })
            .pipe(
              Effect.catchTags({
                SessionNotFoundError: (e) => internalServerError(e),
                AuthError: (e) => internalServerError(e),
              }),
            );
          return { status: true };
        }),
      )
      .handle("orgInvite", ({ params, payload, request }) =>
        Effect.gen(function* () {
          const resolved = yield* requireSession(request, cfg);
          const org = yield* resolveOrganization;
          const invitation = yield* org
            .provideStores(
              org.service.inviteMember(resolved.user.id, params.organizationId, {
                email: payload.email,
                role: payload.role,
              }),
            )
            .pipe(
              Effect.catchTags({
                OrganizationError: (e) => Effect.fail(new S.Forbidden({ message: e.message })),
                AuthError: (e) => internalServerError(e),
              }),
            );
          return encodeInvitation(invitation);
        }),
      )
      .handle("orgListInvitations", ({ params, request }) =>
        Effect.gen(function* () {
          yield* requireSession(request, cfg);
          const org = yield* resolveOrganization;
          const invitations = yield* org
            .provideStores(org.service.listInvitations(params.organizationId))
            .pipe(
              Effect.catchTags({
                AuthError: (e) => internalServerError(e),
              }),
            );
          return invitations.map(encodeInvitation);
        }),
      )
      .handle("orgAcceptInvitation", ({ params, request }) =>
        Effect.gen(function* () {
          const resolved = yield* requireSession(request, cfg);
          const org = yield* resolveOrganization;
          const member = yield* org
            .provideStores(
              org.service.acceptInvitation(
                resolved.user.id,
                params.invitationId,
                resolved.user.email,
              ),
            )
            .pipe(
              Effect.catchTags({
                OrganizationError: (e) => Effect.fail(new S.BadRequest({ message: e.message })),
                AuthError: (e) => internalServerError(e),
              }),
            );
          return encodeMember(member);
        }),
      )
      .handle("orgRejectInvitation", ({ params, request }) =>
        Effect.gen(function* () {
          const resolved = yield* requireSession(request, cfg);
          const org = yield* resolveOrganization;
          const invitation = yield* org
            .provideStores(org.service.rejectInvitation(params.invitationId, resolved.user.email))
            .pipe(
              Effect.catchTags({
                OrganizationError: (e) => Effect.fail(new S.BadRequest({ message: e.message })),
                AuthError: (e) => internalServerError(e),
              }),
            );
          return encodeInvitation(invitation);
        }),
      )
      .handle("orgCancelInvitation", ({ params, request }) =>
        Effect.gen(function* () {
          const resolved = yield* requireSession(request, cfg);
          const org = yield* resolveOrganization;
          const invitation = yield* org
            .provideStores(org.service.cancelInvitation(resolved.user.id, params.invitationId))
            .pipe(
              Effect.catchTags({
                OrganizationError: (e) => Effect.fail(new S.Forbidden({ message: e.message })),
                AuthError: (e) => internalServerError(e),
              }),
            );
          return encodeInvitation(invitation);
        }),
      )
      .handle("orgAddMember", ({ params, payload, request }) =>
        Effect.gen(function* () {
          const resolved = yield* requireSession(request, cfg);
          const org = yield* resolveOrganization;
          const member = yield* org
            .provideStores(
              org.service.addMember(
                resolved.user.id,
                params.organizationId,
                payload.userId,
                payload.role,
              ),
            )
            .pipe(
              Effect.catchTags({
                OrganizationError: (e) => Effect.fail(new S.Forbidden({ message: e.message })),
                AuthError: (e) => internalServerError(e),
              }),
            );
          return encodeMember(member);
        }),
      )
      .handle("orgUpdateMemberRole", ({ params, payload, request }) =>
        Effect.gen(function* () {
          const resolved = yield* requireSession(request, cfg);
          const org = yield* resolveOrganization;
          const member = yield* org
            .provideStores(
              org.service.updateMemberRole(
                resolved.user.id,
                params.organizationId,
                payload.userId,
                payload.role,
              ),
            )
            .pipe(
              Effect.catchTags({
                OrganizationError: (e) => Effect.fail(new S.Forbidden({ message: e.message })),
                AuthError: (e) => internalServerError(e),
              }),
            );
          return encodeMember(member);
        }),
      )
      .handle("orgRemoveMember", ({ params, request }) =>
        Effect.gen(function* () {
          const resolved = yield* requireSession(request, cfg);
          const org = yield* resolveOrganization;
          yield* org
            .provideStores(
              org.service.removeMember(resolved.user.id, params.organizationId, params.userId),
            )
            .pipe(
              Effect.catchTags({
                OrganizationError: (e) => Effect.fail(new S.Forbidden({ message: e.message })),
                AuthError: (e) => internalServerError(e),
              }),
            );
        }),
      )
      // --- Admin ------------------------------------------------------------
      .handle("adminListUsers", ({ payload, request }) =>
        Effect.gen(function* () {
          const resolved = yield* requireSession(request, cfg);
          const admin = yield* resolveAdmin;
          const result = yield* admin
            .provideStores(
              admin.service.listUsers(resolved.user, {
                ...(payload.limit !== undefined && { limit: payload.limit }),
                ...(payload.offset !== undefined && { offset: payload.offset }),
                ...(payload.searchEmail !== undefined && { searchEmail: payload.searchEmail }),
              }),
            )
            .pipe(
              Effect.catchTags({
                AdminError: (e) => Effect.fail(new S.Forbidden({ message: e.message })),
                AuthError: (e) => internalServerError(e),
              }),
            );
          return { users: result.users.map(S.encodeUser), total: result.total };
        }),
      )
      .handle("adminSetRole", ({ payload, request }) =>
        Effect.gen(function* () {
          const resolved = yield* requireSession(request, cfg);
          const admin = yield* resolveAdmin;
          const user = yield* admin.service
            .setRole(resolved.user, payload.userId, payload.role)
            .pipe(
              Effect.catchTags({
                AdminError: (e) => Effect.fail(new S.Forbidden({ message: e.message })),
                UserNotFoundError: (e) => Effect.fail(new S.BadRequest({ message: e.message })),
                AuthError: (e) => internalServerError(e),
              }),
            );
          return S.encodeUser(user);
        }),
      )
      .handle("adminBanUser", ({ payload, request }) =>
        Effect.gen(function* () {
          const resolved = yield* requireSession(request, cfg);
          const admin = yield* resolveAdmin;
          const user = yield* admin.service
            .banUser(resolved.user, payload.userId, {
              ...(payload.reason !== undefined && { reason: payload.reason }),
              ...(payload.expiresIn !== undefined && { expiresIn: payload.expiresIn }),
            })
            .pipe(
              Effect.catchTags({
                AdminError: (e) => Effect.fail(new S.Forbidden({ message: e.message })),
                UserNotFoundError: (e) => Effect.fail(new S.BadRequest({ message: e.message })),
                AuthError: (e) => internalServerError(e),
              }),
            );
          return S.encodeUser(user);
        }),
      )
      .handle("adminUnbanUser", ({ payload, request }) =>
        Effect.gen(function* () {
          const resolved = yield* requireSession(request, cfg);
          const admin = yield* resolveAdmin;
          const user = yield* admin.service.unbanUser(resolved.user, payload.userId).pipe(
            Effect.catchTags({
              AdminError: (e) => Effect.fail(new S.Forbidden({ message: e.message })),
              UserNotFoundError: (e) => Effect.fail(new S.BadRequest({ message: e.message })),
              AuthError: (e) => internalServerError(e),
            }),
          );
          return S.encodeUser(user);
        }),
      )
      .handle("adminRemoveUser", ({ payload, request }) =>
        Effect.gen(function* () {
          const resolved = yield* requireSession(request, cfg);
          const admin = yield* resolveAdmin;
          yield* admin.service.removeUser(resolved.user, payload.userId).pipe(
            Effect.catchTags({
              AdminError: (e) => Effect.fail(new S.Forbidden({ message: e.message })),
              AuthError: (e) => internalServerError(e),
            }),
          );
        }),
      )
      .handle("adminRevokeSessions", ({ payload, request }) =>
        Effect.gen(function* () {
          const resolved = yield* requireSession(request, cfg);
          const admin = yield* resolveAdmin;
          yield* admin.service.revokeUserSessions(resolved.user, payload.userId).pipe(
            Effect.catchTags({
              AdminError: (e) => Effect.fail(new S.Forbidden({ message: e.message })),
              AuthError: (e) => internalServerError(e),
            }),
          );
          return { status: true };
        }),
      )
      .handle("adminImpersonate", ({ payload, request }) =>
        Effect.gen(function* () {
          const resolved = yield* requireSession(request, cfg);
          const admin = yield* resolveAdmin;
          const userService = yield* UserService;
          const session = yield* admin.service.impersonateUser(resolved.user, payload.userId).pipe(
            Effect.catchTags({
              AdminError: (e) => Effect.fail(new S.Forbidden({ message: e.message })),
              UserNotFoundError: (e) => Effect.fail(new S.BadRequest({ message: e.message })),
              AuthError: (e) => internalServerError(e),
              RateLimitError: (e) => Effect.fail(new S.TooManyRequests({ message: e.message })),
              AccountLockedError: (e) =>
                resolveMessage(e.code, e.message).pipe(
                  Effect.flatMap((msg) =>
                    Effect.fail(new S.Forbidden({ message: msg, code: e.code })),
                  ),
                ),
              UserBannedError: (e) =>
                resolveMessage(e.code, e.message).pipe(
                  Effect.flatMap((msg) =>
                    Effect.fail(new S.Forbidden({ message: msg, code: e.code })),
                  ),
                ),
              CaptchaError: (e) =>
                resolveMessage(e.code, e.message).pipe(
                  Effect.flatMap((msg) =>
                    Effect.fail(new S.BadRequest({ message: msg, code: e.code })),
                  ),
                ),
              PwnedPasswordError: (e) =>
                resolveMessage(e.code, e.message).pipe(
                  Effect.flatMap((msg) =>
                    Effect.fail(new S.BadRequest({ message: msg, code: e.code })),
                  ),
                ),
            }),
          );
          const user = yield* userService
            .getUser(session.userId)
            .pipe(Effect.catch(internalServerError));
          const body: S.AuthSuccess = {
            user: S.encodeUser(user),
            needsEmailVerification: false,
          };
          return yield* withSessionCookie(body, session, cfg);
        }),
      )
      .handle("adminStopImpersonating", ({ request }) =>
        Effect.gen(function* () {
          yield* resolveAdmin; // 404 when admin is not enabled
          const resolved = yield* requireSession(request, cfg);
          const sessionManager = yield* SessionManager;
          yield* sessionManager
            .invalidateSession(resolved.session.id)
            .pipe(Effect.catch(internalServerError));
          return yield* HttpServerResponse.json({ status: true }).pipe(
            Effect.flatMap((response) =>
              HttpServerResponse.setCookie(response, cfg.name, "", clearCookieOptions(cfg)),
            ),
            Effect.flatMap((response) =>
              cfg.cache !== undefined
                ? HttpServerResponse.setCookie(
                    response,
                    dataCookieName(cfg),
                    "",
                    clearCookieOptions(cfg),
                  )
                : Effect.succeed(response),
            ),
            Effect.orDie,
          );
        }),
      )
      // --- API keys ---------------------------------------------------------
      .handle("apiKeyCreate", ({ payload, request }) =>
        Effect.gen(function* () {
          const resolved = yield* requireSession(request, cfg);
          const apiKey = yield* resolveApiKey;
          const result = yield* apiKey
            .provideStores(
              apiKey.service.create(resolved.user.id, {
                ...(payload.name !== undefined && { name: payload.name }),
                ...(payload.prefix !== undefined && { prefix: payload.prefix }),
                ...(payload.expiresIn !== undefined && { expiresIn: payload.expiresIn }),
                ...(payload.permissions !== undefined && { permissions: payload.permissions }),
                ...(payload.metadata !== undefined && { metadata: payload.metadata }),
                ...(payload.remaining !== undefined && { remaining: payload.remaining }),
                ...(payload.rateLimit !== undefined && { rateLimit: payload.rateLimit }),
              }),
            )
            .pipe(
              Effect.catchTags({
                ApiKeyError: (e) => Effect.fail(new S.BadRequest({ message: e.message })),
                AuthError: (e) => internalServerError(e),
              }),
            );
          return { key: result.key, apiKey: encodeApiKey(result.apiKey) };
        }),
      )
      .handle("apiKeyList", ({ request }) =>
        Effect.gen(function* () {
          const resolved = yield* requireSession(request, cfg);
          const apiKey = yield* resolveApiKey;
          const keys = yield* apiKey.provideStores(apiKey.service.list(resolved.user.id)).pipe(
            Effect.catchTags({
              AuthError: (e) => internalServerError(e),
            }),
          );
          return keys.map(encodeApiKey);
        }),
      )
      .handle("apiKeyUpdate", ({ params, payload, request }) =>
        Effect.gen(function* () {
          const resolved = yield* requireSession(request, cfg);
          const apiKey = yield* resolveApiKey;
          const updated = yield* apiKey
            .provideStores(
              apiKey.service.update(resolved.user.id, params.keyId, {
                ...(payload.name !== undefined && { name: payload.name }),
                ...(payload.enabled !== undefined && { enabled: payload.enabled }),
                ...(payload.expiresAt !== undefined && { expiresAt: payload.expiresAt }),
                ...(payload.permissions !== undefined && { permissions: payload.permissions }),
                ...(payload.metadata !== undefined && { metadata: payload.metadata }),
                ...(payload.remaining !== undefined && { remaining: payload.remaining }),
                ...(payload.rateLimit !== undefined && { rateLimit: payload.rateLimit }),
              }),
            )
            .pipe(
              Effect.catchTags({
                ApiKeyError: (e) => Effect.fail(new S.BadRequest({ message: e.message })),
                AuthError: (e) => internalServerError(e),
              }),
            );
          return encodeApiKey(updated);
        }),
      )
      .handle("apiKeyDelete", ({ params, request }) =>
        Effect.gen(function* () {
          const resolved = yield* requireSession(request, cfg);
          const apiKey = yield* resolveApiKey;
          yield* apiKey.provideStores(apiKey.service.delete(resolved.user.id, params.keyId)).pipe(
            Effect.catchTags({
              ApiKeyError: (e) => Effect.fail(new S.BadRequest({ message: e.message })),
              AuthError: (e) => internalServerError(e),
            }),
          );
        }),
      )
      // --- Enterprise SSO ---------------------------------------------------
      .handle("ssoRegister", ({ payload, request }) =>
        Effect.gen(function* () {
          const resolved = yield* requireSession(request, cfg);
          if (!isAdmin(resolved.user)) {
            return yield* new S.Forbidden({ message: "Admin privileges required" });
          }
          const sso = yield* resolveSso;
          const provider = yield* sso
            .provideStores(
              sso.service.registerProvider(resolved.user.id, {
                issuer: payload.issuer,
                domain: payload.domain,
                clientId: payload.clientId,
                clientSecret: payload.clientSecret,
                redirectUri: payload.redirectUri,
                ...(payload.discover !== undefined && { discover: payload.discover }),
                ...(payload.authorizationEndpoint !== undefined && {
                  authorizationEndpoint: payload.authorizationEndpoint,
                }),
                ...(payload.tokenEndpoint !== undefined && {
                  tokenEndpoint: payload.tokenEndpoint,
                }),
                ...(payload.userInfoEndpoint !== undefined && {
                  userInfoEndpoint: payload.userInfoEndpoint,
                }),
                ...(payload.jwksEndpoint !== undefined && { jwksEndpoint: payload.jwksEndpoint }),
                ...(payload.scopes !== undefined && { scopes: payload.scopes }),
                ...(payload.usePKCE !== undefined && { usePKCE: payload.usePKCE }),
                ...(payload.organizationId !== undefined && {
                  organizationId: payload.organizationId,
                }),
              }),
            )
            .pipe(
              Effect.catchTags({
                SsoError: (e) => Effect.fail(new S.BadRequest({ message: e.message })),
                AuthError: (e) => internalServerError(e),
              }),
            );
          return encodeSsoProvider(provider);
        }),
      )
      .handle("signInSso", ({ payload }) =>
        Effect.gen(function* () {
          const sso = yield* resolveSso;
          const result = yield* sso
            .provideStores(
              sso.service.signIn({
                ...(payload.email !== undefined && { email: payload.email }),
                ...(payload.domain !== undefined && { domain: payload.domain }),
                ...(payload.providerId !== undefined && { providerId: payload.providerId }),
              }),
            )
            .pipe(
              Effect.catchTags({
                SsoError: (e) => Effect.fail(new S.BadRequest({ message: e.message })),
                AuthError: (e) => internalServerError(e),
              }),
            );
          return { url: result.url, state: result.state };
        }),
      )
      .handle("ssoCallback", ({ payload }) =>
        Effect.gen(function* () {
          const sso = yield* resolveSso;
          const result = yield* sso
            .provideStores(sso.service.handleCallback(payload.state, payload.code))
            .pipe(
              Effect.catchTags({
                SsoError: (e) => Effect.fail(new S.BadRequest({ message: e.message })),
                AuthError: (e) => internalServerError(e),
                RateLimitError: (e) => Effect.fail(new S.TooManyRequests({ message: e.message })),
                AccountLockedError: (e) =>
                  resolveMessage(e.code, e.message).pipe(
                    Effect.flatMap((msg) =>
                      Effect.fail(new S.Forbidden({ message: msg, code: e.code })),
                    ),
                  ),
                UserBannedError: (e) =>
                  resolveMessage(e.code, e.message).pipe(
                    Effect.flatMap((msg) =>
                      Effect.fail(new S.Forbidden({ message: msg, code: e.code })),
                    ),
                  ),
                CaptchaError: (e) =>
                  resolveMessage(e.code, e.message).pipe(
                    Effect.flatMap((msg) =>
                      Effect.fail(new S.BadRequest({ message: msg, code: e.code })),
                    ),
                  ),
                PwnedPasswordError: (e) =>
                  resolveMessage(e.code, e.message).pipe(
                    Effect.flatMap((msg) =>
                      Effect.fail(new S.BadRequest({ message: msg, code: e.code })),
                    ),
                  ),
              }),
            );
          const body: S.AuthSuccess = {
            user: S.encodeUser(result.user),
            needsEmailVerification: false,
          };
          return yield* withSessionCookie(body, result.session, cfg, "sso");
        }),
      )
      // --- JWT --------------------------------------------------------------
      .handle("jwtToken", ({ request }) =>
        Effect.gen(function* () {
          const resolved = yield* requireSession(request, cfg);
          const jwt = yield* resolveJwt;
          const result = yield* jwt.provideStores(jwt.service.sign(resolved.user)).pipe(
            Effect.catchTags({
              JwtError: (e) => internalServerError(e),
              AuthError: (e) => internalServerError(e),
            }),
          );
          return { token: result.token, expiresAt: result.expiresAt };
        }),
      )
      .handle("jwtJwks", () =>
        Effect.gen(function* () {
          const jwt = yield* resolveJwt;
          const jwks = yield* jwt.provideStores(jwt.service.getJwks()).pipe(
            Effect.catchTags({
              AuthError: (e) => internalServerError(e),
            }),
          );
          return { keys: jwks.keys.map((k) => ({ ...k })) };
        }),
      )
      // --- OIDC provider ------------------------------------------------------
      .handle("oidcRegisterClient", ({ payload, request }) =>
        Effect.gen(function* () {
          const resolved = yield* requireSession(request, cfg);
          if (!isAdmin(resolved.user)) {
            return yield* new S.Forbidden({ message: "Admin privileges required" });
          }
          const oidc = yield* resolveOidcProvider;
          const result = yield* oidc
            .provideStores(
              oidc.service.registerClient(
                {
                  name: payload.name,
                  redirectUris: payload.redirectUris,
                  ...(payload.type !== undefined && { type: payload.type }),
                  ...(payload.skipConsent !== undefined && { skipConsent: payload.skipConsent }),
                  ...(payload.metadata !== undefined && { metadata: payload.metadata }),
                },
                resolved.user.id,
              ),
            )
            .pipe(
              Effect.catchTags({
                OidcProviderError: (e) => Effect.fail(new S.BadRequest({ message: e.message })),
                AuthError: (e) => internalServerError(e),
              }),
            );
          return {
            client: encodeOidcClient(result.client),
            ...(result.clientSecret !== undefined && { clientSecret: result.clientSecret }),
          };
        }),
      )
      .handle("oidcListClients", ({ request }) =>
        Effect.gen(function* () {
          const resolved = yield* requireSession(request, cfg);
          if (!isAdmin(resolved.user)) {
            return yield* new S.Forbidden({ message: "Admin privileges required" });
          }
          const oidc = yield* resolveOidcProvider;
          const clients = yield* oidc.provideStores(oidc.service.listClients()).pipe(
            Effect.catchTags({
              AuthError: (e) => internalServerError(e),
            }),
          );
          return clients.map(encodeOidcClient);
        }),
      )
      .handle("oidcUpdateClient", ({ params, payload, request }) =>
        Effect.gen(function* () {
          const resolved = yield* requireSession(request, cfg);
          if (!isAdmin(resolved.user)) {
            return yield* new S.Forbidden({ message: "Admin privileges required" });
          }
          const oidc = yield* resolveOidcProvider;
          const updated = yield* oidc
            .provideStores(
              oidc.service.updateClient(params.clientId, {
                ...(payload.name !== undefined && { name: payload.name }),
                ...(payload.redirectUris !== undefined && {
                  redirectUris: payload.redirectUris,
                }),
                ...(payload.skipConsent !== undefined && { skipConsent: payload.skipConsent }),
                ...(payload.disabled !== undefined && { disabled: payload.disabled }),
                ...(payload.metadata !== undefined && { metadata: payload.metadata }),
              }),
            )
            .pipe(
              Effect.catchTags({
                OidcProviderError: (e) => Effect.fail(new S.BadRequest({ message: e.message })),
                AuthError: (e) => internalServerError(e),
              }),
            );
          return encodeOidcClient(updated);
        }),
      )
      .handle("oidcDeleteClient", ({ params, request }) =>
        Effect.gen(function* () {
          const resolved = yield* requireSession(request, cfg);
          if (!isAdmin(resolved.user)) {
            return yield* new S.Forbidden({ message: "Admin privileges required" });
          }
          const oidc = yield* resolveOidcProvider;
          yield* oidc.provideStores(oidc.service.deleteClient(params.clientId)).pipe(
            Effect.catchTags({
              OidcProviderError: (e) => Effect.fail(new S.BadRequest({ message: e.message })),
              AuthError: (e) => internalServerError(e),
            }),
          );
        }),
      )
      .handle("oidcAuthorize", ({ query, request }) =>
        Effect.gen(function* () {
          const oidc = yield* resolveOidcProvider;
          // Unauthenticated: redirect to the login page carrying the original
          // authorize URL so the app can resume the flow after sign-in.
          const session = yield* resolveSession(request, cfg).pipe(
            Effect.catch(() => Effect.succeed(null)),
          );
          if (session === null) {
            return HttpServerResponse.redirect(oidc.service.loginRedirect(request.url), {
              status: 302,
            });
          }
          // Missing client/redirect_uri cannot be answered with a redirect
          // (there is nowhere trustworthy to send the user) -> 400.
          if (query.client_id === undefined || query.redirect_uri === undefined) {
            return yield* new S.BadRequest({
              message: "client_id and redirect_uri are required",
            });
          }
          const result = yield* oidc
            .provideStores(
              oidc.service.authorize(session.resolved.user, {
                responseType: query.response_type ?? "",
                clientId: query.client_id,
                redirectUri: query.redirect_uri,
                ...(query.scope !== undefined && { scope: query.scope }),
                ...(query.state !== undefined && { state: query.state }),
                ...(query.code_challenge !== undefined && {
                  codeChallenge: query.code_challenge,
                }),
                ...(query.code_challenge_method !== undefined && {
                  codeChallengeMethod: query.code_challenge_method,
                }),
                ...(query.nonce !== undefined && { nonce: query.nonce }),
                ...(query.prompt !== undefined && { prompt: query.prompt }),
              }),
            )
            .pipe(
              Effect.catchTags({
                OidcProviderError: (e) => Effect.fail(new S.BadRequest({ message: e.message })),
                AuthError: (e) => internalServerError(e),
              }),
            );
          return HttpServerResponse.redirect(result.redirectTo, { status: 302 });
        }),
      )
      .handle("oidcConsent", ({ payload, request }) =>
        Effect.gen(function* () {
          const oidc = yield* resolveOidcProvider;
          const resolved = yield* requireSession(request, cfg);
          const result = yield* oidc
            .provideStores(
              oidc.service.consent(resolved.user.id, payload.consentCode, payload.accept),
            )
            .pipe(
              Effect.catchTags({
                OidcProviderError: (e) => Effect.fail(new S.BadRequest({ message: e.message })),
                AuthError: (e) => internalServerError(e),
              }),
            );
          return { redirectTo: result.redirectTo };
        }),
      )
      .handle("oidcToken", ({ payload, request }) =>
        Effect.gen(function* () {
          const oidc = yield* resolveOidcProvider;
          // Client authentication: a Basic Authorization header takes
          // precedence over body credentials (RFC 6749 §2.3.1).
          let clientId = payload.client_id;
          let clientSecret = payload.client_secret;
          const auth = request.headers["authorization"];
          if (auth !== undefined && auth.startsWith("Basic ")) {
            const decoded = Buffer.from(auth.slice(6), "base64").toString("utf8");
            const sep = decoded.indexOf(":");
            if (sep >= 0) {
              clientId = decodeURIComponent(decoded.slice(0, sep));
              clientSecret = decodeURIComponent(decoded.slice(sep + 1));
            }
          }
          const result = yield* oidc
            .provideStores(
              oidc.service.token({
                grantType: payload.grant_type,
                ...(payload.code !== undefined && { code: payload.code }),
                ...(payload.redirect_uri !== undefined && {
                  redirectUri: payload.redirect_uri,
                }),
                ...(payload.code_verifier !== undefined && {
                  codeVerifier: payload.code_verifier,
                }),
                ...(payload.refresh_token !== undefined && {
                  refreshToken: payload.refresh_token,
                }),
                ...(clientId !== undefined && { clientId }),
                ...(clientSecret !== undefined && { clientSecret }),
              }),
            )
            .pipe(
              Effect.catchTags({
                // RFC 6749 error codes: invalid_client -> 401, the rest -> 400.
                OidcTokenError: (e) =>
                  Effect.fail(
                    e.error === "invalid_client"
                      ? new S.Unauthorized({ message: e.error })
                      : new S.BadRequest({ message: e.error }),
                  ),
                AuthError: (e) => internalServerError(e),
              }),
            );
          return {
            access_token: result.accessToken,
            token_type: result.tokenType,
            expires_in: result.expiresIn,
            ...(result.refreshToken !== undefined && { refresh_token: result.refreshToken }),
            ...(result.idToken !== undefined && { id_token: result.idToken }),
            scope: result.scope,
          };
        }),
      )
      .handle("oidcUserInfo", ({ request }) =>
        Effect.gen(function* () {
          const oidc = yield* resolveOidcProvider;
          const auth = request.headers["authorization"];
          const token =
            auth !== undefined && auth.startsWith("Bearer ") ? auth.slice(7) : undefined;
          if (token === undefined) {
            return yield* new S.Unauthorized({ message: "Missing bearer token" });
          }
          return yield* oidc.provideStores(oidc.service.userinfo(token)).pipe(
            Effect.catchTags({
              OidcProviderError: (e) => Effect.fail(new S.Unauthorized({ message: e.message })),
              AuthError: (e) => internalServerError(e),
            }),
          );
        }),
      )
      .handle("oidcDiscovery", () =>
        Effect.gen(function* () {
          const oidc = yield* resolveOidcProvider;
          return oidc.service.getMetadata();
        }),
      )
      .handle("oidcJwks", () =>
        Effect.gen(function* () {
          yield* resolveOidcProvider; // 404 when the OIDC provider is disabled
          const jwt = yield* resolveJwt;
          const jwks = yield* jwt.provideStores(jwt.service.getJwks()).pipe(
            Effect.catchTags({
              AuthError: (e) => internalServerError(e),
            }),
          );
          return { keys: jwks.keys.map((k) => ({ ...k })) };
        }),
      )
      // --- Google One Tap -------------------------------------------------------
      .handle("getGoogleOneTapNonce", () =>
        Effect.gen(function* () {
          const oneTap = yield* resolveGoogleOneTap;
          const nonce = yield* oneTap.provideStores(oneTap.service.createNonce()).pipe(
            Effect.catchTags({
              GoogleOneTapError: (e) => internalServerError(e),
              AuthError: (e) => internalServerError(e),
            }),
          );
          return { nonce };
        }),
      )
      .handle("signInGoogleOneTap", ({ payload }) =>
        Effect.gen(function* () {
          const oneTap = yield* resolveGoogleOneTap;
          const result = yield* oneTap
            .provideStores(oneTap.service.signIn(payload.credential, payload.nonce))
            .pipe(
              Effect.catchTags({
                GoogleOneTapError: (e) => Effect.fail(new S.Unauthorized({ message: e.message })),
                AuthError: (e) => internalServerError(e),
                RateLimitError: (e) => Effect.fail(new S.TooManyRequests({ message: e.message })),
                AccountLockedError: (e) =>
                  resolveMessage(e.code, e.message).pipe(
                    Effect.flatMap((msg) =>
                      Effect.fail(new S.Forbidden({ message: msg, code: e.code })),
                    ),
                  ),
                UserBannedError: (e) =>
                  resolveMessage(e.code, e.message).pipe(
                    Effect.flatMap((msg) =>
                      Effect.fail(new S.Forbidden({ message: msg, code: e.code })),
                    ),
                  ),
                CaptchaError: (e) =>
                  resolveMessage(e.code, e.message).pipe(
                    Effect.flatMap((msg) =>
                      Effect.fail(new S.BadRequest({ message: msg, code: e.code })),
                    ),
                  ),
                PwnedPasswordError: (e) =>
                  resolveMessage(e.code, e.message).pipe(
                    Effect.flatMap((msg) =>
                      Effect.fail(new S.BadRequest({ message: msg, code: e.code })),
                    ),
                  ),
              }),
            );
          const body: S.AuthSuccess = {
            user: S.encodeUser(result.user),
            needsEmailVerification: false,
          };
          return yield* withSessionCookie(body, result.session, cfg, "google");
        }),
      ),
  );
};

/**
 * Build the `AuthSuccess` response (with session cookie) for a redeemed
 * second-factor challenge. The two-factor service returns only `userId` +
 * `session`, so the full user is fetched through the core `UserService`.
 */
const secondFactorSuccess = (
  result: { readonly userId: string; readonly session: Types.Session },
  cfg: ResolvedCookieConfig,
  method?: string,
) =>
  Effect.gen(function* () {
    const userService = yield* UserService;
    const user = yield* userService.getUser(result.userId).pipe(Effect.catch(internalServerError));
    const body: S.AuthSuccess = {
      user: S.encodeUser(user),
      needsEmailVerification: false,
    };
    return yield* withSessionCookie(body, result.session, cfg, method);
  });

/** Resolve and validate the request's session or fail with 401. */
/**
 * Resolve the authenticated session, preferring the signed cache cookie (no
 * store read) when the cache is enabled and the cookie is valid; otherwise
 * validating against the session store. `cacheHit` lets callers decide whether
 * to (re)issue the cache cookie.
 */
const resolveSession = (
  request: HttpServerRequest.HttpServerRequest,
  cfg: ResolvedCookieConfig,
): Effect.Effect<
  { readonly resolved: Types.SessionWithUser; readonly cacheHit: boolean },
  S.Unauthorized,
  SessionManager | Hooks
> =>
  Effect.gen(function* () {
    if (cfg.cache !== undefined) {
      const primaryId = sessionIdFromRequest(request, cfg);
      if (primaryId !== undefined) {
        const cached = request.cookies[dataCookieName(cfg)];
        if (cached !== undefined) {
          const resolved = decodeSessionCacheCookie(cached, cfg.cache, Date.now(), primaryId);
          if (resolved !== null) return { resolved, cacheHit: true };
        }
      }
    }
    const sessionId = sessionIdFromRequest(request, cfg);
    if (sessionId === undefined) {
      return yield* new S.Unauthorized({ message: "Not authenticated" });
    }
    const sessionManager = yield* SessionManager;
    const resolved = yield* sessionManager.validateSession(sessionId).pipe(
      Effect.catchTag("UserBannedError", (e) =>
        resolveMessage(e.code, e.message).pipe(
          Effect.flatMap((msg) => Effect.fail(new S.Unauthorized({ message: msg, code: e.code }))),
        ),
      ),
      Effect.mapError(() => new S.Unauthorized({ message: "Invalid or expired session" })),
    );
    return { resolved, cacheHit: false };
  });

const requireSession = (
  request: HttpServerRequest.HttpServerRequest,
  cfg: ResolvedCookieConfig,
): Effect.Effect<Types.SessionWithUser, S.Unauthorized, SessionManager | Hooks> =>
  resolveSession(request, cfg).pipe(Effect.map((r) => r.resolved));

/**
 * Attach the session cookie to a JSON `AuthSuccess` response when a session is
 * present. When the last-login-method hint is enabled and `method` is given,
 * also (re)writes the non-httpOnly `${name}_last_method` cookie.
 *
 * When `rememberMe` is `false`, a browser-session cookie is emitted (no
 * `Max-Age`/`Expires`) so the cookie is cleared when the browser closes.
 * The server-side session lifetime is unchanged; orphaned sessions expire via
 * the normal idle/absolute-lifetime checks.
 */
const withSessionCookie = (
  body: S.AuthSuccess,
  session: Types.Session | undefined,
  cfg: ResolvedCookieConfig,
  method?: string,
  rememberMe?: boolean,
) =>
  Effect.gen(function* () {
    const json = yield* HttpServerResponse.json(body);
    if (session === undefined) return json;
    const cookieOpts =
      rememberMe === false
        ? sessionOnlyCookieOptions(cfg)
        : sessionCookieOptions(cfg, session.expiresAt);
    let response = yield* HttpServerResponse.setCookie(json, cfg.name, session.id, cookieOpts);
    // Multi-session: append the new session to the device's session list (the
    // primary cookie remains the active session), capped to `maximumSessions`.
    if (cfg.multiSession !== undefined) {
      const request = yield* HttpServerRequest.HttpServerRequest;
      const existing = readDeviceSessionIds(request, cfg).filter((id) => id !== session.id);
      const ids = [...existing, session.id].slice(-cfg.multiSession.maximumSessions);
      response = yield* HttpServerResponse.setCookie(
        response,
        multiCookieName(cfg),
        ids.join("."),
        cookieOpts,
      );
    }
    // Last-login-method hint: a page-readable cookie login UIs use to
    // highlight the user's previous sign-in method.
    if (cfg.lastLoginMethod !== undefined && method !== undefined) {
      response = yield* HttpServerResponse.setCookie(
        response,
        lastMethodCookieName(cfg),
        method,
        lastMethodCookieOptions(cfg, cfg.lastLoginMethod.maxAge),
      );
    }
    return response;
  }).pipe(Effect.orDie);

// -----------------------------------------------------------------------------
// Web handler
// -----------------------------------------------------------------------------

/**
 * Runtime-agnostic platform services required by the HttpApi router. We never
 * serve files, so a no-op `FileSystem` suffices; it is both provided to
 * `HttpPlatform` and exposed in the output (the router requires `FileSystem`
 * directly too).
 */
const PlatformLayer = Layer.mergeAll(Etag.layer, Path.layer, HttpPlatform.layer).pipe(
  Layer.provideMerge(FileSystem.layerNoop({})),
);

// ---------------------------------------------------------------------------
// Per-endpoint IP rate limiting (HTTP layer)
// ---------------------------------------------------------------------------

/**
 * A single per-endpoint IP rate-limit rule.
 * `path` is matched against the request pathname (exact string or regex).
 * `methods` limits the rule to specific HTTP methods (default: all methods).
 */
export interface EndpointRateLimitRule {
  readonly path: string | RegExp;
  /** HTTP methods this rule applies to (uppercase). Default: all. */
  readonly methods?: ReadonlyArray<string>;
  readonly maxRequests: number;
  readonly windowMs: number;
  readonly blockDurationMs?: number;
}

/**
 * IP rate-limiting configuration for the HTTP layer.
 *
 * When `rules` is omitted, {@link defaultEndpointRules} is used — sane
 * defaults for all sensitive auth endpoints.
 */
export interface HttpIpRateLimitConfig {
  /**
   * Declarative rule set. First matching rule (in order) wins.
   * Omit to use the built-in defaults for all sensitive endpoints.
   */
  readonly rules?: ReadonlyArray<EndpointRateLimitRule>;
}

/**
 * Sane default IP rate-limit rules applied to sensitive auth endpoints.
 *
 * | Endpoint(s)                            | Limit            | Window   | Block    |
 * |----------------------------------------|------------------|----------|----------|
 * | `/sign-in`, `/sign-in/*`               | 10 req           | 15 min   | 30 min   |
 * | `/sign-up`                             | 5 req            | 1 hr     | 24 hr    |
 * | `/magic-link/send`, `/email-otp/send`  | 5 req            | 10 min   | 30 min   |
 * | `/phone-otp/send`                      | 5 req            | 10 min   | 30 min   |
 * | `/password-reset/request`              | 5 req            | 1 hr     | 2 hr     |
 * | `/two-factor/verify-*`                 | 10 req           | 5 min    | 30 min   |
 */
export const defaultEndpointRules: ReadonlyArray<EndpointRateLimitRule> = [
  {
    path: /^\/sign-in(\/.*)?$/,
    methods: ["POST"],
    maxRequests: 10,
    windowMs: 15 * 60 * 1000,
    blockDurationMs: 30 * 60 * 1000,
  },
  {
    path: "/sign-up",
    methods: ["POST"],
    maxRequests: 5,
    windowMs: 60 * 60 * 1000,
    blockDurationMs: 24 * 60 * 60 * 1000,
  },
  {
    path: /^\/(magic-link|email-otp|phone-otp)\/send$/,
    methods: ["POST"],
    maxRequests: 5,
    windowMs: 10 * 60 * 1000,
    blockDurationMs: 30 * 60 * 1000,
  },
  {
    path: "/password-reset/request",
    methods: ["POST"],
    maxRequests: 5,
    windowMs: 60 * 60 * 1000,
    blockDurationMs: 2 * 60 * 60 * 1000,
  },
  {
    path: /^\/two-factor\/verify-/,
    methods: ["POST"],
    maxRequests: 10,
    windowMs: 5 * 60 * 1000,
    blockDurationMs: 30 * 60 * 1000,
  },
];

const matchesEndpointRule = (
  rule: EndpointRateLimitRule,
  pathname: string,
  method: string,
): boolean => {
  if (rule.methods !== undefined && !rule.methods.includes(method.toUpperCase())) return false;
  return typeof rule.path === "string" ? rule.path === pathname : rule.path.test(pathname);
};

const findEndpointRule = (
  rules: ReadonlyArray<EndpointRateLimitRule>,
  pathname: string,
  method: string,
): EndpointRateLimitRule | undefined => rules.find((r) => matchesEndpointRule(r, pathname, method));

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
   * requests, in addition to the request's own origin.
   *
   * **CSRF protection**: browsers attach an `Origin` header to cross-origin
   * (and most same-origin) mutating requests. When the header is present and
   * matches neither the request URL's origin nor this list, the request is
   * rejected with `403`. When `Origin` is absent but `Referer` is present
   * (e.g. a plain HTML form submission), the `Referer` origin is used as a
   * fallback. Requests with neither header (curl, server-to-server) are
   * allowed through.
   *
   * **Host trust**: the request URL's origin is derived from the `Host` header
   * as seen by the application. When deployed behind a reverse proxy you MUST
   * configure {@link trustedProxy} (from issue #81 / `ClientIp`) so the proxy
   * forwards the correct `Host` and the origin comparison is accurate.
   *
   * Note: `GET /token` (JWT issuance) is treated as state-changing and
   * therefore also subject to this check.
   */
  readonly trustedOrigins?: ReadonlyArray<string>;
  /**
   * Maximum allowed request-body size in bytes. Requests whose
   * `Content-Length` header exceeds this limit are rejected with `413 Payload
   * Too Large` before the body is read or decoded. Default `65536` (64 KiB).
   *
   * Note: `Content-Length` is advisory — a client that omits it or sends a
   * chunked body bypasses this check. Pair with a reverse-proxy body-size
   * limit for a complete defence.
   */
  readonly maxBodySize?: number;
  /**
   * Serve the generated OpenAPI document and an API reference UI. When `true`,
   * `GET {prefix}/openapi.json` returns the OpenAPI 3.1 document and
   * `GET {prefix}/reference` returns a Scalar reference page. Default `false`
   * (keep off in production unless you intend to expose the docs publicly).
   */
  readonly docs?: boolean;
  /**
   * Trusted-proxy configuration for resolving the real client IP.
   *
   * **Secure default**: without this option, all `X-Forwarded-For` and similar
   * headers are IGNORED and the socket remote address is used as-is.
   *
   * Provide this only when the app is deployed behind a known reverse proxy.
   * The resolved IP is available to all hooks and handlers via
   * `Effect.serviceOption(ClientIp)`.
   */
  readonly trustedProxy?: TrustedProxyConfig;
  /**
   * Enable IP-keyed rate limiting at the HTTP boundary, before handlers run.
   *
   * Requires `RateLimiter` and `RateLimitStore` in the `services` layer.
   * Requests that exceed a limit receive HTTP 429 before any auth logic runs.
   *
   * Set to `{}` to use the built-in {@link defaultEndpointRules}, or supply
   * `{ rules: [...] }` for a custom rule set.
   */
  readonly ipRateLimit?: HttpIpRateLimitConfig;
}

/** Minimal Scalar API reference shell pointing at the sibling `openapi.json`. */
const scalarReferenceHtml = `<!doctype html>
<html>
  <head>
    <title>effect-auth API reference</title>
    <meta charset="utf-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1" />
  </head>
  <body>
    <script id="api-reference" data-url="openapi.json"></script>
    <script src="https://cdn.jsdelivr.net/npm/@scalar/api-reference"></script>
  </body>
</html>
`;

const openApiJsonResponse = (): Response =>
  new Response(JSON.stringify(getOpenApiSpec()), {
    status: 200,
    headers: { "content-type": "application/json" },
  });

const referenceResponse = (): Response =>
  new Response(scalarReferenceHtml, {
    status: 200,
    headers: { "content-type": "text/html; charset=utf-8" },
  });

/**
 * CSRF guard for the web handler.
 *
 * Returns `true` when the request may proceed.
 *
 * @param inner - The path relative to the mount prefix (e.g. `/sign-in`), or
 *   `null` when the request is outside the prefix.  Used to detect `GET /token`
 *   which issues a JWT and must be treated as state-changing.
 */
const isTrustedRequest = (
  request: Request,
  trustedOrigins: ReadonlyArray<string>,
  inner: string | null,
): boolean => {
  const method = request.method.toUpperCase();

  // GET /token issues a signed JWT — treat as state-changing so it is subject
  // to the same origin check as POST requests.
  const isStateSafe =
    (method === "GET" || method === "HEAD" || method === "OPTIONS") && inner !== "/token";
  if (isStateSafe) return true;

  const origin = request.headers.get("origin");

  if (origin !== null) {
    // An opaque "null" origin (sandboxed iframe, some redirects) is NOT trusted
    // unless explicitly listed.
    const requestOrigin = new URL(request.url).origin;
    return origin === requestOrigin || trustedOrigins.includes(origin);
  }

  // No Origin header.  Use Referer as a fallback (plain HTML form submissions,
  // older browsers).  If there is no Referer either the request is likely
  // server-to-server (curl, API clients) — allow through.
  const referer = request.headers.get("referer");
  if (referer === null) return true;
  try {
    const refererOrigin = new URL(referer).origin;
    const requestOrigin = new URL(request.url).origin;
    return refererOrigin === requestOrigin || trustedOrigins.includes(refererOrigin);
  } catch {
    // Malformed Referer — reject to be safe.
    return false;
  }
};

/**
 * Build a standard Web `Request => Response` handler for the auth API.
 *
 * Mount the returned `handler` in any framework (SvelteKit/Next/Hono/...).
 * `dispose` releases the handler's scope.
 */
export const makeAuthWebHandler = (
  options: AuthWebHandlerOptions,
): {
  readonly handler: (request: Request, context?: Context.Context<never>) => Promise<Response>;
  readonly dispose: () => Promise<void>;
} => {
  const apiLayer = HttpApiBuilder.layer(AuthApi).pipe(
    Layer.provide(authGroupLayer(options.cookie, options.multiSession)),
    Layer.provide(PlatformLayer),
  );
  // The handlers' service requirements are tracked as phantom
  // `Request<"Requires", RIn>` types; providing `services` to the layer's OUTPUT
  // (provideMerge) both satisfies them at runtime and zeroes the web handler's
  // leftover context (HR), yielding a plain `(request) => Promise<Response>`.
  const appLayer = apiLayer.pipe(Layer.provideMerge(options.services));

  const ipRateRules = options.ipRateLimit?.rules ?? defaultEndpointRules;

  const web = HttpRouter.toWebHandler(appLayer, {
    // Cast to `Effect<..., never, never>` so TypeScript infers HR = never, keeping the
    // `context` parameter of `web.handler` optional. The cast is safe: HttpServerRequest
    // and Scope are always provided by the server infrastructure before middleware runs.
    middleware: (effect) =>
      Effect.gen(function* () {
        const req = yield* HttpServerRequest.HttpServerRequest;
        const ip = resolveClientIp(req, options.trustedProxy);

        // Per-endpoint IP rate limiting (requires RateLimiter + RateLimitStore in services)
        if (options.ipRateLimit !== undefined && ip !== undefined) {
          const url = new URL(req.url, "http://localhost");
          const rule = findEndpointRule(ipRateRules, url.pathname, req.method);
          if (rule !== undefined) {
            const rateLimiterOpt = yield* Effect.serviceOption(RateLimiter);
            const storeOpt = yield* Effect.serviceOption(RateLimitStore);
            if (Option.isSome(rateLimiterOpt) && Option.isSome(storeOpt)) {
              const limitConfig: RateLimitConfig = {
                maxRequests: rule.maxRequests,
                windowMs: rule.windowMs,
                ...(rule.blockDurationMs !== undefined && {
                  blockDurationMs: rule.blockDurationMs,
                }),
              };
              const denied = yield* rateLimiterOpt.value
                .consumeToken(`ip:${url.pathname}:${ip}`, limitConfig)
                .pipe(
                  Effect.provideService(RateLimitStore, storeOpt.value),
                  Effect.as(null as null),
                  Effect.catchTag("RateLimitError", (e) => Effect.succeed(e)),
                  Effect.catchTag("AuthError", () => Effect.succeed(null)),
                );
              if (denied !== null) {
                return HttpServerResponse.jsonUnsafe(
                  {
                    message: "Too many requests",
                    ...(denied.retryAfter !== undefined && { retryAfter: denied.retryAfter }),
                  },
                  { status: 429 },
                );
              }
            }
          }
        }

        // Provide the resolved ClientIp to all downstream effects (hooks, handlers)
        return yield* effect.pipe(Effect.provideService(ClientIp, { ip }));
      }) as unknown as Effect.Effect<HttpServerResponse.HttpServerResponse, never, never>,
  });

  const trustedOrigins = options.trustedOrigins ?? [];
  const prefix = options.prefix ?? "";
  const docs = options.docs ?? false;
  const maxBodySize = options.maxBodySize ?? 65536; // 64 KiB default

  /** Path relative to the mount `prefix`, or `null` when outside the prefix. */
  const innerPath = (pathname: string): string | null => {
    if (prefix === "") return pathname;
    if (pathname === prefix) return "/";
    if (pathname.startsWith(`${prefix}/`)) return pathname.slice(prefix.length);
    return null;
  };

  const handler = (request: Request, context?: Context.Context<never>): Promise<Response> => {
    const url = new URL(request.url);
    const inner = innerPath(url.pathname);

    // When a non-empty prefix is configured, reject requests that fall outside
    // it with 404 instead of forwarding them to the router where unprefixed
    // paths might accidentally match.
    if (prefix !== "" && inner === null) {
      return Promise.resolve(Response.json({ message: "Not Found" }, { status: 404 }));
    }

    if (!isTrustedRequest(request, trustedOrigins, inner)) {
      return Promise.resolve(Response.json({ message: "Origin not allowed" }, { status: 403 }));
    }

    // Reject bodies that exceed the configured limit before parsing.
    // Content-Length is advisory; complement with a proxy-level limit for full
    // coverage of chunked / omitted-length bodies.
    const contentLength = request.headers.get("content-length");
    if (contentLength !== null) {
      const bytes = parseInt(contentLength, 10);
      if (!isNaN(bytes) && bytes > maxBodySize) {
        return Promise.resolve(Response.json({ message: "Payload too large" }, { status: 413 }));
      }
    }

    if (docs && inner !== null && request.method === "GET") {
      if (inner === "/openapi.json") return Promise.resolve(openApiJsonResponse());
      if (inner === "/reference") return Promise.resolve(referenceResponse());
    }

    if (inner !== null && prefix !== "") {
      url.pathname = inner || "/";
      return web.handler(new Request(url, request), context);
    }
    return web.handler(request, context);
  };
  return { handler, dispose: web.dispose };
};
