import { Effect, Request, RequestResolver } from "effect";
import * as Requests from "./Requests.js";
import * as Errors from "./Errors.js";
import { SessionManagerTag, UserStoreTag } from "./Session.js";
import { PasswordHasherTag } from "./Password.js";
import { AuthLifecycleServiceTag } from "./AuthLifecycle.js";
import { PasswordResetServiceTag } from "./PasswordReset.js";
import { UserServiceTag } from "./User.js";

/*
 * Effect v4 notes:
 *
 * - A resolver that depends on services is expressed as an
 *   `Effect<RequestResolver<...>, never, Services>`. `Effect.request` accepts this
 *   form directly and threads the required services into its own context, so call
 *   sites stay `Effect.request(request, makeXResolver)`.
 * - `RequestResolver.fromEffect` requires the per-entry effect to have `R = never`.
 *   Leaf services (SessionManager, PasswordHasher) already expose `R = never`
 *   methods, so their resolvers call the method directly. Orchestration services
 *   (AuthLifecycle, PasswordReset, User) declare their store dependencies in the
 *   method's `R` channel; for those we capture the ambient context in the builder
 *   and `Effect.provide` it to the per-entry effect. The captured services surface
 *   on the builder's own requirements and flow through to `Effect.request` callers,
 *   so the runtime behaviour is unchanged.
 */

/**
 * Create a resolver for session creation
 */
export const makeCreateSessionResolver = Effect.gen(function* () {
  const sessionManager = yield* SessionManagerTag;
  return RequestResolver.fromEffect((entry: Request.Entry<Requests.CreateSessionRequest>) =>
    sessionManager.createSession(entry.request.userId, entry.request.attributes),
  );
});

/**
 * Create a resolver for session validation
 */
export const makeValidateSessionResolver = Effect.gen(function* () {
  const sessionManager = yield* SessionManagerTag;
  return RequestResolver.fromEffect((entry: Request.Entry<Requests.ValidateSessionRequest>) =>
    sessionManager.validateSession(entry.request.sessionId),
  );
});

/**
 * Create a resolver for session invalidation
 */
export const makeInvalidateSessionResolver = Effect.gen(function* () {
  const sessionManager = yield* SessionManagerTag;
  return RequestResolver.fromEffect((entry: Request.Entry<Requests.InvalidateSessionRequest>) =>
    sessionManager.invalidateSession(entry.request.sessionId),
  );
});

/**
 * Create a resolver for invalidating all user sessions
 */
export const makeInvalidateUserSessionsResolver = Effect.gen(function* () {
  const sessionManager = yield* SessionManagerTag;
  return RequestResolver.fromEffect(
    (entry: Request.Entry<Requests.InvalidateUserSessionsRequest>) =>
      sessionManager.invalidateUserSessions(entry.request.userId),
  );
});

/**
 * Create a resolver for credential verification
 */
export const makeVerifyCredentialsResolver = Effect.gen(function* () {
  const userStore = yield* UserStoreTag;
  const passwordHasher = yield* PasswordHasherTag;
  return RequestResolver.fromEffect((entry: Request.Entry<Requests.VerifyCredentialsRequest>) =>
    Effect.gen(function* () {
      const request = entry.request;

      // Get user and their hashed password
      const user = yield* userStore.get(request.userId);
      const hashedPassword = yield* userStore.getCredentials(request.userId);

      // Verify password
      const isValid = yield* passwordHasher.verify(request.password, hashedPassword);

      if (!isValid) {
        return yield* new Errors.InvalidCredentialsError({
          message: "Invalid credentials",
        });
      }

      return user;
    }),
  );
});

/**
 * Create a resolver for password hashing
 */
export const makeHashPasswordResolver = Effect.gen(function* () {
  const passwordHasher = yield* PasswordHasherTag;
  return RequestResolver.fromEffect((entry: Request.Entry<Requests.HashPasswordRequest>) =>
    passwordHasher.hash(entry.request.password),
  );
});

/**
 * Create a resolver for password verification
 */
export const makeVerifyPasswordResolver = Effect.gen(function* () {
  const passwordHasher = yield* PasswordHasherTag;
  return RequestResolver.fromEffect((entry: Request.Entry<Requests.VerifyPasswordRequest>) =>
    passwordHasher.verify(entry.request.password, entry.request.hash),
  );
});

/**
 * Resolver for SignUpEmailRequest
 */
export const signUpEmailResolver = Effect.gen(function* () {
  const authLifecycle = yield* AuthLifecycleServiceTag;
  const context = yield* Effect.context<Effect.Services<ReturnType<typeof authLifecycle.signUp>>>();
  return RequestResolver.fromEffect((entry: Request.Entry<Requests.SignUpEmailRequest>) =>
    Effect.provide(authLifecycle.signUp(entry.request.input), context),
  );
});

/**
 * Resolver for SignInEmailRequest
 */
export const signInEmailResolver = Effect.gen(function* () {
  const authLifecycle = yield* AuthLifecycleServiceTag;
  const context = yield* Effect.context<Effect.Services<ReturnType<typeof authLifecycle.signIn>>>();
  return RequestResolver.fromEffect((entry: Request.Entry<Requests.SignInEmailRequest>) =>
    Effect.provide(authLifecycle.signIn(entry.request.input), context),
  );
});

/**
 * Resolver for VerifyEmailRequest
 */
export const verifyEmailResolver = Effect.gen(function* () {
  const authLifecycle = yield* AuthLifecycleServiceTag;
  const context =
    yield* Effect.context<Effect.Services<ReturnType<typeof authLifecycle.verifyEmail>>>();
  return RequestResolver.fromEffect((entry: Request.Entry<Requests.VerifyEmailRequest>) =>
    Effect.provide(authLifecycle.verifyEmail(entry.request.input), context),
  );
});

/**
 * Resolver for RequestPasswordResetRequest
 */
export const makeRequestPasswordResetResolver = Effect.gen(function* () {
  const passwordReset = yield* PasswordResetServiceTag;
  const context =
    yield* Effect.context<Effect.Services<ReturnType<typeof passwordReset.requestPasswordReset>>>();
  return RequestResolver.fromEffect((entry: Request.Entry<Requests.RequestPasswordResetRequest>) =>
    Effect.provide(passwordReset.requestPasswordReset(entry.request.email), context),
  );
});

/**
 * Resolver for ResetPasswordRequest
 */
export const makeResetPasswordResolver = Effect.gen(function* () {
  const passwordReset = yield* PasswordResetServiceTag;
  const context =
    yield* Effect.context<Effect.Services<ReturnType<typeof passwordReset.resetPassword>>>();
  return RequestResolver.fromEffect((entry: Request.Entry<Requests.ResetPasswordRequest>) =>
    Effect.provide(
      passwordReset.resetPassword(entry.request.token, entry.request.newPassword),
      context,
    ),
  );
});

/**
 * Resolver for GetUserRequest
 */
export const makeGetUserResolver = Effect.gen(function* () {
  const userService = yield* UserServiceTag;
  const context = yield* Effect.context<Effect.Services<ReturnType<typeof userService.getUser>>>();
  return RequestResolver.fromEffect((entry: Request.Entry<Requests.GetUserRequest>) =>
    Effect.provide(userService.getUser(entry.request.userId), context),
  );
});

/**
 * Resolver for GetUserByEmailRequest
 */
export const makeGetUserByEmailResolver = Effect.gen(function* () {
  const userService = yield* UserServiceTag;
  const context =
    yield* Effect.context<Effect.Services<ReturnType<typeof userService.getUserByEmail>>>();
  return RequestResolver.fromEffect((entry: Request.Entry<Requests.GetUserByEmailRequest>) =>
    Effect.provide(userService.getUserByEmail(entry.request.email), context),
  );
});

/**
 * Resolver for UpdateUserAttributesRequest
 */
export const makeUpdateUserAttributesResolver = Effect.gen(function* () {
  const userService = yield* UserServiceTag;
  const context =
    yield* Effect.context<Effect.Services<ReturnType<typeof userService.updateUserAttributes>>>();
  return RequestResolver.fromEffect((entry: Request.Entry<Requests.UpdateUserAttributesRequest>) =>
    Effect.provide(
      userService.updateUserAttributes(entry.request.userId, entry.request.attributes),
      context,
    ),
  );
});

/**
 * Resolver for MarkEmailVerifiedRequest
 */
export const makeMarkEmailVerifiedResolver = Effect.gen(function* () {
  const userService = yield* UserServiceTag;
  const context =
    yield* Effect.context<Effect.Services<ReturnType<typeof userService.markEmailVerified>>>();
  return RequestResolver.fromEffect((entry: Request.Entry<Requests.MarkEmailVerifiedRequest>) =>
    Effect.provide(userService.markEmailVerified(entry.request.userId), context),
  );
});

/**
 * Resolver for DeleteUserRequest
 */
export const makeDeleteUserResolver = Effect.gen(function* () {
  const userService = yield* UserServiceTag;
  const context =
    yield* Effect.context<Effect.Services<ReturnType<typeof userService.deleteUser>>>();
  return RequestResolver.fromEffect((entry: Request.Entry<Requests.DeleteUserRequest>) =>
    Effect.provide(userService.deleteUser(entry.request.userId), context),
  );
});
