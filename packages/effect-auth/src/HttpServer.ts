import { Context, Effect, FileSystem, Layer, Option, Path } from "effect";
import { HttpApiBuilder } from "effect/unstable/httpapi";
import {
  Etag,
  HttpPlatform,
  HttpRouter,
  HttpServerRequest,
  HttpServerResponse,
} from "effect/unstable/http";
import { AuthApi, getOpenApiSpec } from "./HttpApi.js";
import * as S from "./HttpApiSchemas.js";
import { AuthLifecycleServiceTag } from "./AuthLifecycle.js";
import { Hooks } from "./Hooks.js";
import { SessionManagerTag, UserStoreTag } from "./Session.js";
import { EmailPasswordStoreTag, makeEmailPasswordService } from "./EmailPassword.js";
import { MagicLinkServiceTag, MagicLinkStoreTag, MagicLinkUserStoreTag } from "./MagicLink.js";
import { AccountManagementServiceTag, AccountManagementStoreTag } from "./AccountManagement.js";
import { AnonymousServiceTag, AnonymousUserStoreTag } from "./Anonymous.js";
import { PhoneOtpServiceTag, PhoneOtpStoreTag, PhoneOtpUserStoreTag } from "./PhoneOtp.js";
import { UsernameServiceTag, UsernameStoreTag } from "./Username.js";
import {
  DeviceAuthorizationServiceTag,
  DeviceAuthorizationStoreTag,
} from "./DeviceAuthorization.js";
import { EmailOtpServiceTag, EmailOtpStoreTag, EmailOtpUserStoreTag } from "./EmailOtp.js";
import { PendingTwoFactorStoreTag, TwoFactorServiceTag, TwoFactorStoreTag } from "./TwoFactor.js";
import { PasswordHasherTag } from "./Password.js";
import { EmailVerificationServiceTag, EmailVerificationStoreTag } from "./EmailVerification.js";
import {
  PasswordResetServiceTag,
  PasswordResetStoreTag,
  PasswordResetUserStoreTag,
} from "./PasswordReset.js";
import { UserServiceStoreTag, UserServiceTag } from "./User.js";
import {
  OrganizationServiceTag,
  OrganizationStoreTag,
  type Organization,
  type Member,
  type Invitation,
  type FullOrganization,
} from "./Organization.js";
import { AdminServiceTag, AdminUserStoreTag } from "./Admin.js";
import { ApiKeyServiceTag, ApiKeyStoreTag, type ApiKey } from "./ApiKey.js";
import { JwtServiceTag, JwtKeyStoreTag } from "./Jwt.js";
import {
  decodeSessionCacheCookie,
  encodeSessionCacheCookie,
  resolveSessionCache,
  type ResolvedSessionCache,
  type SessionCacheConfig,
} from "./SessionCookieCache.js";
import type * as Types from "./Types.js";

/**
 * The services the auth handlers require. Your `services` layer must provide
 * all of these (a superset is fine). They are the existing core services plus
 * the stores the orchestration services depend on, plus the `Hooks` service
 * (provide `Hooks.Default` for no-op hooks, or a `composePlugins([...])` stack).
 */
export type AuthServices =
  | AuthLifecycleServiceTag
  | SessionManagerTag
  | EmailPasswordStoreTag
  | PasswordHasherTag
  | EmailVerificationServiceTag
  | EmailVerificationStoreTag
  | PasswordResetServiceTag
  | PasswordResetStoreTag
  | PasswordResetUserStoreTag
  | UserServiceTag
  | UserServiceStoreTag
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
   * Signed session-data cookie cache. When enabled, a short-lived HMAC-signed
   * copy of the session + user is stored in a `${name}_data` cookie so
   * authenticated requests can be served without a session-store read (up to
   * `maxAge`). See {@link SessionCacheConfig}.
   */
  readonly cache?: SessionCacheConfig;
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
}

const resolveCookieConfig = (
  config?: CookieConfig,
  multiSession?: MultiSessionConfig,
): ResolvedCookieConfig => ({
  name: config?.name ?? "conduit_session",
  secure: config?.secure ?? true,
  path: config?.path ?? "/",
  cache: resolveSessionCache(config?.cache),
  multiSession:
    multiSession === undefined ? undefined : { maximumSessions: multiSession.maximumSessions ?? 5 },
});

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
  const service = yield* Effect.serviceOption(MagicLinkServiceTag);
  const store = yield* Effect.serviceOption(MagicLinkStoreTag);
  const userStore = yield* Effect.serviceOption(MagicLinkUserStoreTag);
  if (Option.isNone(service) || Option.isNone(store) || Option.isNone(userStore)) {
    return yield* new S.NotFound({ message: "Magic link is not enabled" });
  }
  const provideStores = <A, E, R>(effect: Effect.Effect<A, E, R>) =>
    effect.pipe(
      Effect.provideService(MagicLinkStoreTag, store.value),
      Effect.provideService(MagicLinkUserStoreTag, userStore.value),
    );
  return { service: service.value, provideStores };
});

/** Resolve the email OTP service + stores, or fail with 404. */
const resolveEmailOtp = Effect.gen(function* () {
  const service = yield* Effect.serviceOption(EmailOtpServiceTag);
  const store = yield* Effect.serviceOption(EmailOtpStoreTag);
  const userStore = yield* Effect.serviceOption(EmailOtpUserStoreTag);
  if (Option.isNone(service) || Option.isNone(store) || Option.isNone(userStore)) {
    return yield* new S.NotFound({ message: "Email OTP is not enabled" });
  }
  const provideStores = <A, E, R>(effect: Effect.Effect<A, E, R>) =>
    effect.pipe(
      Effect.provideService(EmailOtpStoreTag, store.value),
      Effect.provideService(EmailOtpUserStoreTag, userStore.value),
    );
  return { service: service.value, provideStores };
});

/** Resolve the two-factor service + stores, or fail with 404. */
const resolveTwoFactor = Effect.gen(function* () {
  const service = yield* Effect.serviceOption(TwoFactorServiceTag);
  const store = yield* Effect.serviceOption(TwoFactorStoreTag);
  const pendingStore = yield* Effect.serviceOption(PendingTwoFactorStoreTag);
  if (Option.isNone(service) || Option.isNone(store) || Option.isNone(pendingStore)) {
    return yield* new S.NotFound({ message: "Two-factor authentication is not enabled" });
  }
  const provideStores = <A, E, R>(effect: Effect.Effect<A, E, R>) =>
    effect.pipe(
      Effect.provideService(TwoFactorStoreTag, store.value),
      Effect.provideService(PendingTwoFactorStoreTag, pendingStore.value),
    );
  return { service: service.value, provideStores };
});

/** Resolve the account-management service + store, or fail with 404. */
const resolveAccountManagement = Effect.gen(function* () {
  const service = yield* Effect.serviceOption(AccountManagementServiceTag);
  const store = yield* Effect.serviceOption(AccountManagementStoreTag);
  if (Option.isNone(service) || Option.isNone(store)) {
    return yield* new S.NotFound({ message: "Account management is not enabled" });
  }
  const provideStores = <A, E, R>(effect: Effect.Effect<A, E, R>) =>
    effect.pipe(Effect.provideService(AccountManagementStoreTag, store.value));
  return { service: service.value, provideStores };
});

/** Resolve the device-authorization service + store, or fail with 404. */
const resolveDevice = Effect.gen(function* () {
  const service = yield* Effect.serviceOption(DeviceAuthorizationServiceTag);
  const store = yield* Effect.serviceOption(DeviceAuthorizationStoreTag);
  if (Option.isNone(service) || Option.isNone(store)) {
    return yield* new S.NotFound({ message: "Device authorization is not enabled" });
  }
  const provideStores = <A, E, R>(effect: Effect.Effect<A, E, R>) =>
    effect.pipe(Effect.provideService(DeviceAuthorizationStoreTag, store.value));
  return { service: service.value, provideStores };
});

/** Resolve the username service + store, or fail with 404. */
const resolveUsername = Effect.gen(function* () {
  const service = yield* Effect.serviceOption(UsernameServiceTag);
  const store = yield* Effect.serviceOption(UsernameStoreTag);
  if (Option.isNone(service) || Option.isNone(store)) {
    return yield* new S.NotFound({ message: "Username sign-in is not enabled" });
  }
  const provideStores = <A, E, R>(effect: Effect.Effect<A, E, R>) =>
    effect.pipe(Effect.provideService(UsernameStoreTag, store.value));
  return { service: service.value, provideStores };
});

/** Resolve the phone OTP service + stores, or fail with 404. */
const resolvePhoneOtp = Effect.gen(function* () {
  const service = yield* Effect.serviceOption(PhoneOtpServiceTag);
  const store = yield* Effect.serviceOption(PhoneOtpStoreTag);
  const userStore = yield* Effect.serviceOption(PhoneOtpUserStoreTag);
  if (Option.isNone(service) || Option.isNone(store) || Option.isNone(userStore)) {
    return yield* new S.NotFound({ message: "Phone OTP is not enabled" });
  }
  const provideStores = <A, E, R>(effect: Effect.Effect<A, E, R>) =>
    effect.pipe(
      Effect.provideService(PhoneOtpStoreTag, store.value),
      Effect.provideService(PhoneOtpUserStoreTag, userStore.value),
    );
  return { service: service.value, provideStores };
});

/** Resolve the anonymous service + store, or fail with 404. */
const resolveAnonymous = Effect.gen(function* () {
  const service = yield* Effect.serviceOption(AnonymousServiceTag);
  const store = yield* Effect.serviceOption(AnonymousUserStoreTag);
  if (Option.isNone(service) || Option.isNone(store)) {
    return yield* new S.NotFound({ message: "Anonymous sign-in is not enabled" });
  }
  const provideStores = <A, E, R>(effect: Effect.Effect<A, E, R>) =>
    effect.pipe(Effect.provideService(AnonymousUserStoreTag, store.value));
  return { service: service.value, provideStores };
});

/** Resolve the organization service + store, or fail with 404. */
const resolveOrganization = Effect.gen(function* () {
  const service = yield* Effect.serviceOption(OrganizationServiceTag);
  const store = yield* Effect.serviceOption(OrganizationStoreTag);
  if (Option.isNone(service) || Option.isNone(store)) {
    return yield* new S.NotFound({ message: "Organizations are not enabled" });
  }
  const provideStores = <A, E, R>(effect: Effect.Effect<A, E, R>) =>
    effect.pipe(Effect.provideService(OrganizationStoreTag, store.value));
  return { service: service.value, provideStores };
});

/** Resolve the admin service + user store, or fail with 404. */
const resolveAdmin = Effect.gen(function* () {
  const service = yield* Effect.serviceOption(AdminServiceTag);
  const store = yield* Effect.serviceOption(AdminUserStoreTag);
  if (Option.isNone(service) || Option.isNone(store)) {
    return yield* new S.NotFound({ message: "Admin is not enabled" });
  }
  const provideStores = <A, E, R>(effect: Effect.Effect<A, E, R>) =>
    effect.pipe(Effect.provideService(AdminUserStoreTag, store.value));
  return { service: service.value, provideStores };
});

/** Resolve the API-key service + store, or fail with 404. */
const resolveApiKey = Effect.gen(function* () {
  const service = yield* Effect.serviceOption(ApiKeyServiceTag);
  const store = yield* Effect.serviceOption(ApiKeyStoreTag);
  if (Option.isNone(service) || Option.isNone(store)) {
    return yield* new S.NotFound({ message: "API keys are not enabled" });
  }
  const provideStores = <A, E, R>(effect: Effect.Effect<A, E, R>) =>
    effect.pipe(Effect.provideService(ApiKeyStoreTag, store.value));
  return { service: service.value, provideStores };
});

/** Resolve the JWT service + key store, or fail with 404. */
const resolveJwt = Effect.gen(function* () {
  const service = yield* Effect.serviceOption(JwtServiceTag);
  const store = yield* Effect.serviceOption(JwtKeyStoreTag);
  if (Option.isNone(service) || Option.isNone(store)) {
    return yield* new S.NotFound({ message: "JWT is not enabled" });
  }
  const provideStores = <A, E, R>(effect: Effect.Effect<A, E, R>) =>
    effect.pipe(Effect.provideService(JwtKeyStoreTag, store.value));
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

/** Layer implementing the `auth` group handlers. */
export const authGroupLayer = (config?: CookieConfig, multiSession?: MultiSessionConfig) => {
  const cfg = resolveCookieConfig(config, multiSession);

  return HttpApiBuilder.group(AuthApi, "auth", (handlers) =>
    handlers
      .handle("signUp", ({ payload }) =>
        Effect.gen(function* () {
          const lifecycle = yield* AuthLifecycleServiceTag;
          const result = yield* lifecycle.signUp(signUpInput(payload)).pipe(
            Effect.catchTags({
              AuthError: (e) => Effect.fail(new S.Conflict({ message: e.message })),
              EmailNotVerifiedError: (e) => Effect.fail(new S.BadRequest({ message: e.message })),
              HashingError: (e) => Effect.fail(new S.InternalServerError({ message: e.message })),
              EmailVerificationError: (e) =>
                Effect.fail(new S.InternalServerError({ message: e.message })),
              RateLimitError: (e) => Effect.fail(new S.BadRequest({ message: e.message })),
            }),
          );
          const body: S.AuthSuccess = {
            user: S.encodeUser(result.user),
            needsEmailVerification: result.needsEmailVerification,
          };
          return yield* withSessionCookie(body, result.session, cfg);
        }),
      )
      .handle("signIn", ({ payload }) =>
        Effect.gen(function* () {
          const lifecycle = yield* AuthLifecycleServiceTag;
          const result = yield* lifecycle
            .signIn({
              email: payload.email,
              password: payload.password,
              ...(payload.captchaToken !== undefined && { captchaToken: payload.captchaToken }),
            })
            .pipe(
              Effect.catchTags({
                InvalidCredentialsError: (e) =>
                  Effect.fail(new S.Unauthorized({ message: e.message })),
                AuthError: (e) => Effect.fail(new S.InternalServerError({ message: e.message })),
                HashingError: (e) => Effect.fail(new S.InternalServerError({ message: e.message })),
                EmailVerificationError: (e) =>
                  Effect.fail(new S.InternalServerError({ message: e.message })),
                RateLimitError: (e) => Effect.fail(new S.Forbidden({ message: e.message })),
              }),
            );
          const body: S.AuthSuccess = {
            user: S.encodeUser(result.user),
            needsEmailVerification: result.needsEmailVerification,
            ...(result.secondFactor !== undefined && { secondFactor: result.secondFactor }),
          };
          return yield* withSessionCookie(body, result.session, cfg);
        }),
      )
      .handle("signOut", ({ request }) =>
        Effect.gen(function* () {
          const sessionId = sessionIdFromRequest(request, cfg);
          if (sessionId !== undefined) {
            const sessionManager = yield* SessionManagerTag;
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
            const value = encodeSessionCacheCookie(resolved, cache, Date.now());
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
          const store = yield* EmailPasswordStoreTag;
          const verification = yield* EmailVerificationServiceTag;
          const email = payload.email.trim().toLowerCase();

          const user = yield* store
            .getUserByEmail(email)
            .pipe(Effect.mapError((e) => new S.InternalServerError({ message: e.message })));

          // Anti-enumeration: succeed uniformly whether or not the user exists
          // (or is already verified).
          if (user !== null && !user.emailVerified) {
            yield* verification.resendVerification(user.id, email).pipe(
              Effect.catchTags({
                AuthError: (e) => Effect.fail(new S.InternalServerError({ message: e.message })),
                EmailVerificationError: (e) =>
                  Effect.fail(new S.InternalServerError({ message: e.message })),
                RateLimitError: (e) => Effect.fail(new S.BadRequest({ message: e.message })),
              }),
            );
          }

          return { status: true };
        }),
      )
      .handle("verifyEmail", ({ payload }) =>
        Effect.gen(function* () {
          const lifecycle = yield* AuthLifecycleServiceTag;
          const result = yield* lifecycle.verifyEmail({ token: payload.token }).pipe(
            Effect.catchTags({
              EmailVerificationError: (e) => Effect.fail(new S.BadRequest({ message: e.message })),
              UserNotFoundError: (e) => Effect.fail(new S.BadRequest({ message: e.message })),
              AuthError: (e) => Effect.fail(new S.InternalServerError({ message: e.message })),
              RateLimitError: (e) => Effect.fail(new S.BadRequest({ message: e.message })),
            }),
          );
          const body: S.AuthSuccess = {
            user: S.encodeUser(result.user),
            needsEmailVerification: result.needsEmailVerification,
          };
          return yield* withSessionCookie(body, result.session, cfg);
        }),
      )
      .handle("requestPasswordReset", ({ payload }) =>
        Effect.gen(function* () {
          const passwordReset = yield* PasswordResetServiceTag;
          yield* passwordReset.requestPasswordReset(payload.email).pipe(
            Effect.catchTags({
              AuthError: (e) => Effect.fail(new S.InternalServerError({ message: e.message })),
              PasswordResetError: (e) =>
                Effect.fail(new S.InternalServerError({ message: e.message })),
              RateLimitError: (e) => Effect.fail(new S.BadRequest({ message: e.message })),
            }),
          );
          return { status: true };
        }),
      )
      .handle("resetPassword", ({ payload }) =>
        Effect.gen(function* () {
          const passwordReset = yield* PasswordResetServiceTag;
          yield* passwordReset.resetPassword(payload.token, payload.newPassword).pipe(
            Effect.catchTags({
              PasswordResetError: (e) => Effect.fail(new S.BadRequest({ message: e.message })),
              AuthError: (e) => Effect.fail(new S.InternalServerError({ message: e.message })),
              HashingError: (e) => Effect.fail(new S.InternalServerError({ message: e.message })),
              RateLimitError: (e) => Effect.fail(new S.BadRequest({ message: e.message })),
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
                  Effect.fail(new S.BadRequest({ message: e.message })),
                AuthError: (e) => Effect.fail(new S.BadRequest({ message: e.message })),
                HashingError: (e) => Effect.fail(new S.InternalServerError({ message: e.message })),
              }),
            );
        }),
      )
      .handle("updateUser", ({ payload, request }) =>
        Effect.gen(function* () {
          const resolved = yield* requireSession(request, cfg);
          const userService = yield* UserServiceTag;
          const updated = yield* userService
            .updateUser(resolved.user.id, {
              ...(payload.name !== undefined && { name: payload.name }),
              ...(payload.image !== undefined && { image: payload.image }),
            })
            .pipe(
              Effect.catchTags({
                UserNotFoundError: () =>
                  Effect.fail(new S.Unauthorized({ message: "Not authenticated" })),
                AuthError: (e) => Effect.fail(new S.InternalServerError({ message: e.message })),
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
                AuthError: (e) => Effect.fail(new S.InternalServerError({ message: e.message })),
              }),
            );
          return { status: true };
        }),
      )
      .handle("changeEmailConfirm", ({ payload }) =>
        Effect.gen(function* () {
          const account = yield* resolveAccountManagement;
          yield* account.provideStores(account.service.confirmEmailChange(payload.token)).pipe(
            Effect.catchTags({
              AccountTokenError: (e) => Effect.fail(new S.BadRequest({ message: e.message })),
              UserNotFoundError: (e) => Effect.fail(new S.BadRequest({ message: e.message })),
              AuthError: (e) => Effect.fail(new S.InternalServerError({ message: e.message })),
            }),
          );
          return { status: true };
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
                AuthError: (e) => Effect.fail(new S.InternalServerError({ message: e.message })),
              }),
            );
          return { status: true };
        }),
      )
      .handle("deleteUserConfirm", ({ payload }) =>
        Effect.gen(function* () {
          const account = yield* resolveAccountManagement;
          yield* account.provideStores(account.service.confirmAccountDeletion(payload.token)).pipe(
            Effect.catchTags({
              AccountTokenError: (e) => Effect.fail(new S.BadRequest({ message: e.message })),
              UserNotFoundError: (e) => Effect.fail(new S.BadRequest({ message: e.message })),
              AuthError: (e) => Effect.fail(new S.InternalServerError({ message: e.message })),
            }),
          );
          return { status: true };
        }),
      )
      .handle("listSessions", ({ request }) =>
        Effect.gen(function* () {
          const resolved = yield* requireSession(request, cfg);
          const sessionManager = yield* SessionManagerTag;
          const sessions = yield* sessionManager
            .listSessions(resolved.user.id)
            .pipe(Effect.mapError((e) => new S.InternalServerError({ message: e.message })));
          return sessions.map(S.encodeSession);
        }),
      )
      .handle("revokeSession", ({ params, request }) =>
        Effect.gen(function* () {
          const resolved = yield* requireSession(request, cfg);
          const sessionManager = yield* SessionManagerTag;

          const sessions = yield* sessionManager
            .listSessions(resolved.user.id)
            .pipe(Effect.mapError((e) => new S.InternalServerError({ message: e.message })));

          // Only the owner may revoke a session, and only their own sessions.
          const target = sessions.find((session) => session.id === params.sessionId);
          if (target === undefined) {
            return yield* new S.BadRequest({ message: "Session not found" });
          }

          yield* sessionManager
            .invalidateSession(target.id)
            .pipe(Effect.mapError((e) => new S.InternalServerError({ message: e.message })));
        }),
      )
      .handle("revokeOtherSessions", ({ request }) =>
        Effect.gen(function* () {
          const resolved = yield* requireSession(request, cfg);
          const sessionManager = yield* SessionManagerTag;
          yield* sessionManager
            .revokeOtherSessions(resolved.user.id, resolved.session.id)
            .pipe(Effect.mapError((e) => new S.InternalServerError({ message: e.message })));
        }),
      )
      .handle("magicLinkSend", ({ payload }) =>
        Effect.gen(function* () {
          const magicLink = yield* resolveMagicLink;
          // Anti-enumeration: the service succeeds silently for unknown
          // accounts; only store/delivery failures surface (as 500).
          yield* magicLink.provideStores(magicLink.service.send(payload.email)).pipe(
            Effect.catchTags({
              AuthError: (e) => Effect.fail(new S.InternalServerError({ message: e.message })),
              MagicLinkError: (e) => Effect.fail(new S.InternalServerError({ message: e.message })),
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
                AuthError: (e) => Effect.fail(new S.InternalServerError({ message: e.message })),
                RateLimitError: (e) => Effect.fail(new S.BadRequest({ message: e.message })),
              }),
            );
          const body: S.AuthSuccess = {
            user: S.encodeUser(result.user),
            needsEmailVerification: false,
          };
          return yield* withSessionCookie(body, result.session, cfg);
        }),
      )
      .handle("emailOtpSend", ({ payload }) =>
        Effect.gen(function* () {
          const emailOtp = yield* resolveEmailOtp;
          // Anti-enumeration: the service succeeds silently for unknown
          // accounts; only store/delivery failures surface (as 500).
          yield* emailOtp.provideStores(emailOtp.service.send(payload.email, payload.purpose)).pipe(
            Effect.catchTags({
              AuthError: (e) => Effect.fail(new S.InternalServerError({ message: e.message })),
              EmailOtpError: (e) => Effect.fail(new S.InternalServerError({ message: e.message })),
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
                AuthError: (e) => Effect.fail(new S.InternalServerError({ message: e.message })),
                RateLimitError: (e) => Effect.fail(new S.BadRequest({ message: e.message })),
              }),
            );
          const body: S.AuthSuccess = {
            user: S.encodeUser(result.user),
            needsEmailVerification: false,
          };
          return yield* withSessionCookie(body, result.session, cfg);
        }),
      )
      .handle("signInAnonymous", () =>
        Effect.gen(function* () {
          const anonymous = yield* resolveAnonymous;
          const result = yield* anonymous.provideStores(anonymous.service.signInAnonymous()).pipe(
            Effect.catchTags({
              AuthError: (e) => Effect.fail(new S.InternalServerError({ message: e.message })),
              RateLimitError: (e) => Effect.fail(new S.InternalServerError({ message: e.message })),
            }),
          );
          const body: S.AuthSuccess = {
            user: S.encodeUser(result.user),
            needsEmailVerification: false,
          };
          return yield* withSessionCookie(body, result.session, cfg);
        }),
      )
      .handle("signInUsername", ({ payload }) =>
        Effect.gen(function* () {
          const username = yield* resolveUsername;
          const result = yield* username
            .provideStores(
              username.service.signIn({ username: payload.username, password: payload.password }),
            )
            .pipe(
              Effect.catchTags({
                UsernameError: (e) => Effect.fail(new S.Unauthorized({ message: e.message })),
                InvalidCredentialsError: (e) =>
                  Effect.fail(new S.Unauthorized({ message: e.message })),
                HashingError: (e) => Effect.fail(new S.InternalServerError({ message: e.message })),
                AuthError: (e) => Effect.fail(new S.InternalServerError({ message: e.message })),
                RateLimitError: (e) => Effect.fail(new S.Unauthorized({ message: e.message })),
              }),
            );
          const body: S.AuthSuccess = {
            user: S.encodeUser(result.user),
            needsEmailVerification: false,
            ...(result.secondFactor !== undefined && { secondFactor: result.secondFactor }),
          };
          return yield* withSessionCookie(body, result.session, cfg);
        }),
      )
      .handle("multiSessionList", ({ request }) =>
        Effect.gen(function* () {
          if (cfg.multiSession === undefined) {
            return yield* new S.NotFound({ message: "Multi-session is not enabled" });
          }
          const sessionManager = yield* SessionManagerTag;
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
          const sessionManager = yield* SessionManagerTag;
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
            Effect.orDie,
          );
        }),
      )
      .handle("multiSessionRevoke", ({ payload, request }) =>
        Effect.gen(function* () {
          if (cfg.multiSession === undefined) {
            return yield* new S.NotFound({ message: "Multi-session is not enabled" });
          }
          const sessionManager = yield* SessionManagerTag;
          yield* sessionManager
            .invalidateSession(payload.sessionId)
            .pipe(Effect.mapError((e) => new S.InternalServerError({ message: e.message })));

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
                AuthError: (e) => Effect.fail(new S.InternalServerError({ message: e.message })),
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
              SessionNotFoundError: (e) =>
                Effect.fail(new S.InternalServerError({ message: e.message })),
              SessionExpiredError: (e) =>
                Effect.fail(new S.InternalServerError({ message: e.message })),
              UserNotFoundError: (e) =>
                Effect.fail(new S.InternalServerError({ message: e.message })),
              AuthError: (e) => Effect.fail(new S.InternalServerError({ message: e.message })),
              RateLimitError: (e) => Effect.fail(new S.BadRequest({ message: e.message })),
            }),
          );
          const body: S.AuthSuccess = {
            user: S.encodeUser(result.user),
            needsEmailVerification: false,
          };
          return yield* withSessionCookie(body, result.session, cfg);
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
                AuthError: (e) => Effect.fail(new S.InternalServerError({ message: e.message })),
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
              AuthError: (e) => Effect.fail(new S.InternalServerError({ message: e.message })),
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
                PhoneOtpError: (e) =>
                  Effect.fail(new S.InternalServerError({ message: e.message })),
                AuthError: (e) => Effect.fail(new S.InternalServerError({ message: e.message })),
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
                AuthError: (e) => Effect.fail(new S.InternalServerError({ message: e.message })),
                RateLimitError: (e) => Effect.fail(new S.BadRequest({ message: e.message })),
              }),
            );
          const body: S.AuthSuccess = {
            user: S.encodeUser(result.user),
            needsEmailVerification: false,
          };
          return yield* withSessionCookie(body, result.session, cfg);
        }),
      )
      .handle("twoFactorEnable", ({ payload, request }) =>
        Effect.gen(function* () {
          const resolved = yield* requireSession(request, cfg);
          const twoFactor = yield* resolveTwoFactor;
          // `enable` labels the otpauth:// URI with the user's email via the
          // core UserStore, which is not part of `AuthServices` - resolve it
          // optionally alongside the feature.
          const userStore = yield* Effect.serviceOption(UserStoreTag);
          if (Option.isNone(userStore)) {
            return yield* new S.NotFound({ message: "Two-factor authentication is not enabled" });
          }
          return yield* twoFactor
            .provideStores(twoFactor.service.enable(resolved.user.id, payload.password))
            .pipe(
              Effect.provideService(UserStoreTag, userStore.value),
              Effect.catchTags({
                InvalidCredentialsError: (e) =>
                  Effect.fail(new S.BadRequest({ message: e.message })),
                TwoFactorError: (e) =>
                  Effect.fail(new S.InternalServerError({ message: e.message })),
                UserNotFoundError: (e) =>
                  Effect.fail(new S.InternalServerError({ message: e.message })),
                HashingError: (e) => Effect.fail(new S.InternalServerError({ message: e.message })),
                AuthError: (e) => Effect.fail(new S.InternalServerError({ message: e.message })),
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
                HashingError: (e) => Effect.fail(new S.InternalServerError({ message: e.message })),
                AuthError: (e) => Effect.fail(new S.InternalServerError({ message: e.message })),
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
                HashingError: (e) => Effect.fail(new S.InternalServerError({ message: e.message })),
                AuthError: (e) => Effect.fail(new S.InternalServerError({ message: e.message })),
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
                HashingError: (e) => Effect.fail(new S.InternalServerError({ message: e.message })),
                AuthError: (e) => Effect.fail(new S.InternalServerError({ message: e.message })),
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
                HashingError: (e) => Effect.fail(new S.InternalServerError({ message: e.message })),
                AuthError: (e) => Effect.fail(new S.InternalServerError({ message: e.message })),
                RateLimitError: (e) => Effect.fail(new S.BadRequest({ message: e.message })),
              }),
            );
          return yield* secondFactorSuccess(result, cfg);
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
                AuthError: (e) => Effect.fail(new S.InternalServerError({ message: e.message })),
                RateLimitError: (e) => Effect.fail(new S.BadRequest({ message: e.message })),
              }),
            );
          return yield* secondFactorSuccess(result, cfg);
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
                AuthError: (e) => Effect.fail(new S.InternalServerError({ message: e.message })),
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
                AuthError: (e) => Effect.fail(new S.InternalServerError({ message: e.message })),
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
                AuthError: (e) => Effect.fail(new S.InternalServerError({ message: e.message })),
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
                AuthError: (e) => Effect.fail(new S.InternalServerError({ message: e.message })),
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
                AuthError: (e) => Effect.fail(new S.InternalServerError({ message: e.message })),
              }),
            );
        }),
      )
      .handle("orgSetActive", ({ payload, request }) =>
        Effect.gen(function* () {
          yield* resolveOrganization; // 404 when organizations are not enabled
          const resolved = yield* requireSession(request, cfg);
          const sessionManager = yield* SessionManagerTag;
          yield* sessionManager
            .setSessionAttributes(resolved.session.id, {
              activeOrganizationId: payload.organizationId,
            })
            .pipe(
              Effect.catchTags({
                SessionNotFoundError: (e) =>
                  Effect.fail(new S.InternalServerError({ message: e.message })),
                AuthError: (e) => Effect.fail(new S.InternalServerError({ message: e.message })),
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
                AuthError: (e) => Effect.fail(new S.InternalServerError({ message: e.message })),
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
                AuthError: (e) => Effect.fail(new S.InternalServerError({ message: e.message })),
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
                AuthError: (e) => Effect.fail(new S.InternalServerError({ message: e.message })),
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
                AuthError: (e) => Effect.fail(new S.InternalServerError({ message: e.message })),
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
                AuthError: (e) => Effect.fail(new S.InternalServerError({ message: e.message })),
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
                AuthError: (e) => Effect.fail(new S.InternalServerError({ message: e.message })),
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
                AuthError: (e) => Effect.fail(new S.InternalServerError({ message: e.message })),
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
                AuthError: (e) => Effect.fail(new S.InternalServerError({ message: e.message })),
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
                AuthError: (e) => Effect.fail(new S.InternalServerError({ message: e.message })),
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
                AuthError: (e) => Effect.fail(new S.InternalServerError({ message: e.message })),
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
                AuthError: (e) => Effect.fail(new S.InternalServerError({ message: e.message })),
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
              AuthError: (e) => Effect.fail(new S.InternalServerError({ message: e.message })),
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
              AuthError: (e) => Effect.fail(new S.InternalServerError({ message: e.message })),
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
              AuthError: (e) => Effect.fail(new S.InternalServerError({ message: e.message })),
            }),
          );
          return { status: true };
        }),
      )
      .handle("adminImpersonate", ({ payload, request }) =>
        Effect.gen(function* () {
          const resolved = yield* requireSession(request, cfg);
          const admin = yield* resolveAdmin;
          const userService = yield* UserServiceTag;
          const session = yield* admin.service.impersonateUser(resolved.user, payload.userId).pipe(
            Effect.catchTags({
              AdminError: (e) => Effect.fail(new S.Forbidden({ message: e.message })),
              UserNotFoundError: (e) => Effect.fail(new S.BadRequest({ message: e.message })),
              AuthError: (e) => Effect.fail(new S.InternalServerError({ message: e.message })),
              RateLimitError: (e) => Effect.fail(new S.InternalServerError({ message: e.message })),
            }),
          );
          const user = yield* userService
            .getUser(session.userId)
            .pipe(Effect.mapError((e) => new S.InternalServerError({ message: e.message })));
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
          const sessionManager = yield* SessionManagerTag;
          yield* sessionManager
            .invalidateSession(resolved.session.id)
            .pipe(Effect.mapError((e) => new S.InternalServerError({ message: e.message })));
          return yield* HttpServerResponse.json({ status: true }).pipe(
            Effect.flatMap((response) =>
              HttpServerResponse.setCookie(response, cfg.name, "", clearCookieOptions(cfg)),
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
                AuthError: (e) => Effect.fail(new S.InternalServerError({ message: e.message })),
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
              AuthError: (e) => Effect.fail(new S.InternalServerError({ message: e.message })),
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
                AuthError: (e) => Effect.fail(new S.InternalServerError({ message: e.message })),
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
              AuthError: (e) => Effect.fail(new S.InternalServerError({ message: e.message })),
            }),
          );
        }),
      )
      // --- JWT --------------------------------------------------------------
      .handle("jwtToken", ({ request }) =>
        Effect.gen(function* () {
          const resolved = yield* requireSession(request, cfg);
          const jwt = yield* resolveJwt;
          const result = yield* jwt.provideStores(jwt.service.sign(resolved.user)).pipe(
            Effect.catchTags({
              JwtError: (e) => Effect.fail(new S.InternalServerError({ message: e.message })),
              AuthError: (e) => Effect.fail(new S.InternalServerError({ message: e.message })),
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
              AuthError: (e) => Effect.fail(new S.InternalServerError({ message: e.message })),
            }),
          );
          return { keys: jwks.keys.map((k) => ({ ...k })) };
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
) =>
  Effect.gen(function* () {
    const userService = yield* UserServiceTag;
    const user = yield* userService
      .getUser(result.userId)
      .pipe(Effect.mapError((e) => new S.InternalServerError({ message: e.message })));
    const body: S.AuthSuccess = {
      user: S.encodeUser(user),
      needsEmailVerification: false,
    };
    return yield* withSessionCookie(body, result.session, cfg);
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
  SessionManagerTag | Hooks
> =>
  Effect.gen(function* () {
    if (cfg.cache !== undefined) {
      const cached = request.cookies[dataCookieName(cfg)];
      if (cached !== undefined) {
        const resolved = decodeSessionCacheCookie(cached, cfg.cache, Date.now());
        if (resolved !== null) return { resolved, cacheHit: true };
      }
    }
    const sessionId = sessionIdFromRequest(request, cfg);
    if (sessionId === undefined) {
      return yield* new S.Unauthorized({ message: "Not authenticated" });
    }
    const sessionManager = yield* SessionManagerTag;
    const resolved = yield* sessionManager
      .validateSession(sessionId)
      .pipe(Effect.mapError(() => new S.Unauthorized({ message: "Invalid or expired session" })));
    return { resolved, cacheHit: false };
  });

const requireSession = (
  request: HttpServerRequest.HttpServerRequest,
  cfg: ResolvedCookieConfig,
): Effect.Effect<Types.SessionWithUser, S.Unauthorized, SessionManagerTag | Hooks> =>
  resolveSession(request, cfg).pipe(Effect.map((r) => r.resolved));

/** Attach the session cookie to a JSON `AuthSuccess` response when a session is present. */
const withSessionCookie = (
  body: S.AuthSuccess,
  session: Types.Session | undefined,
  cfg: ResolvedCookieConfig,
) =>
  Effect.gen(function* () {
    const json = yield* HttpServerResponse.json(body);
    if (session === undefined) return json;
    let response = yield* HttpServerResponse.setCookie(
      json,
      cfg.name,
      session.id,
      sessionCookieOptions(cfg, session.expiresAt),
    );
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
        sessionCookieOptions(cfg, session.expiresAt),
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
   * (non-GET/HEAD/OPTIONS) requests, in addition to the request's own origin.
   *
   * Browsers attach an `Origin` header to cross-origin (and most same-origin)
   * mutating requests; when the header is present and matches neither the
   * request URL's origin nor this list, the request is rejected with `403`
   * before it reaches a handler (CSRF protection). Requests without an
   * `Origin` header (curl, server-to-server) are allowed through.
   */
  readonly trustedOrigins?: ReadonlyArray<string>;
  /**
   * Serve the generated OpenAPI document and an API reference UI. When `true`,
   * `GET {prefix}/openapi.json` returns the OpenAPI 3.1 document and
   * `GET {prefix}/reference` returns a Scalar reference page. Default `false`
   * (keep off in production unless you intend to expose the docs publicly).
   */
  readonly docs?: boolean;
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

/** CSRF check shared by the web handler. Returns `true` when allowed. */
const isTrustedRequest = (request: Request, trustedOrigins: ReadonlyArray<string>): boolean => {
  const method = request.method.toUpperCase();
  if (method === "GET" || method === "HEAD" || method === "OPTIONS") return true;

  const origin = request.headers.get("origin");
  // No Origin header: non-browser client (curl, server-to-server) - allow.
  // An opaque "null" origin (sandboxed iframe, some redirects) is NOT trusted
  // unless explicitly listed.
  if (origin === null) return true;

  const requestOrigin = new URL(request.url).origin;
  return origin === requestOrigin || trustedOrigins.includes(origin);
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
  const web = HttpRouter.toWebHandler(appLayer);

  const trustedOrigins = options.trustedOrigins ?? [];
  const prefix = options.prefix ?? "";
  const docs = options.docs ?? false;

  /** Path relative to the mount `prefix`, or `null` when outside the prefix. */
  const innerPath = (pathname: string): string | null => {
    if (prefix === "") return pathname;
    if (pathname === prefix) return "/";
    if (pathname.startsWith(`${prefix}/`)) return pathname.slice(prefix.length);
    return null;
  };

  const handler = (request: Request, context?: Context.Context<never>): Promise<Response> => {
    if (!isTrustedRequest(request, trustedOrigins)) {
      return Promise.resolve(Response.json({ message: "Origin not allowed" }, { status: 403 }));
    }
    const url = new URL(request.url);
    const inner = innerPath(url.pathname);

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
