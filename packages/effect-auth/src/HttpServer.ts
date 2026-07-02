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
}

interface ResolvedCookieConfig {
  readonly name: string;
  readonly secure: boolean;
  readonly path: string;
}

const resolveCookieConfig = (config?: CookieConfig): ResolvedCookieConfig => ({
  name: config?.name ?? "conduit_session",
  secure: config?.secure ?? true,
  path: config?.path ?? "/",
});

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

/** Layer implementing the `auth` group handlers. */
export const authGroupLayer = (config?: CookieConfig) => {
  const cfg = resolveCookieConfig(config);

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
            .signIn({ email: payload.email, password: payload.password })
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
          return yield* HttpServerResponse.setCookie(
            HttpServerResponse.empty({ status: 204 }),
            cfg.name,
            "",
            clearCookieOptions(cfg),
          ).pipe(Effect.orDie);
        }),
      )
      .handle("getSession", ({ request }) =>
        Effect.gen(function* () {
          const resolved = yield* requireSession(request, cfg);
          return S.encodeSessionWithUser(resolved);
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
const requireSession = (
  request: HttpServerRequest.HttpServerRequest,
  cfg: ResolvedCookieConfig,
): Effect.Effect<Types.SessionWithUser, S.Unauthorized, SessionManagerTag | Hooks> =>
  Effect.gen(function* () {
    const sessionId = sessionIdFromRequest(request, cfg);
    if (sessionId === undefined) {
      return yield* new S.Unauthorized({ message: "Not authenticated" });
    }
    const sessionManager = yield* SessionManagerTag;
    return yield* sessionManager
      .validateSession(sessionId)
      .pipe(Effect.mapError(() => new S.Unauthorized({ message: "Invalid or expired session" })));
  });

/** Attach the session cookie to a JSON `AuthSuccess` response when a session is present. */
const withSessionCookie = (
  body: S.AuthSuccess,
  session: Types.Session | undefined,
  cfg: ResolvedCookieConfig,
) =>
  Effect.gen(function* () {
    const response = yield* HttpServerResponse.json(body);
    if (session === undefined) return response;
    return yield* HttpServerResponse.setCookie(
      response,
      cfg.name,
      session.id,
      sessionCookieOptions(cfg, session.expiresAt),
    );
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
    Layer.provide(authGroupLayer(options.cookie)),
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
