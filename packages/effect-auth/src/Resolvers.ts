import { Effect, RequestResolver } from "effect";
import * as Requests from "./Requests.js";
import * as Errors from "./Errors.js";
import { SessionManagerTag, UserStoreTag } from "./Session.js";
import { PasswordHasherTag } from "./Password.js";
import { AuthLifecycleServiceTag } from "./AuthLifecycle.js";
import { PasswordResetServiceTag } from "./PasswordReset.js";
import { UserServiceTag } from "./User.js";

/**
 * Create a resolver for session creation
 */
export const makeCreateSessionResolver = RequestResolver.fromEffect(
  (request: Requests.CreateSessionRequest) =>
    Effect.gen(function* () {
      const sessionManager = yield* SessionManagerTag;
      return yield* sessionManager.createSession(request.userId, request.attributes);
    }),
);

/**
 * Create a resolver for session validation
 */
export const makeValidateSessionResolver = RequestResolver.fromEffect(
  (request: Requests.ValidateSessionRequest) =>
    Effect.gen(function* () {
      const sessionManager = yield* SessionManagerTag;
      return yield* sessionManager.validateSession(request.sessionId);
    }),
);

/**
 * Create a resolver for session invalidation
 */
export const makeInvalidateSessionResolver = RequestResolver.fromEffect(
  (request: Requests.InvalidateSessionRequest) =>
    Effect.gen(function* () {
      const sessionManager = yield* SessionManagerTag;
      return yield* sessionManager.invalidateSession(request.sessionId);
    }),
);

/**
 * Create a resolver for invalidating all user sessions
 */
export const makeInvalidateUserSessionsResolver = RequestResolver.fromEffect(
  (request: Requests.InvalidateUserSessionsRequest) =>
    Effect.gen(function* () {
      const sessionManager = yield* SessionManagerTag;
      return yield* sessionManager.invalidateUserSessions(request.userId);
    }),
);

/**
 * Create a resolver for credential verification
 */
export const makeVerifyCredentialsResolver = RequestResolver.fromEffect(
  (request: Requests.VerifyCredentialsRequest) =>
    Effect.gen(function* () {
      const userStore = yield* UserStoreTag;
      const passwordHasher = yield* PasswordHasherTag;

      // Get user and their hashed password
      const user = yield* userStore.get(request.userId);
      const hashedPassword = yield* userStore.getCredentials(request.userId);

      // Verify password
      const isValid = yield* passwordHasher.verify(request.password, hashedPassword);

      if (!isValid) {
        return yield* Effect.fail(
          new Errors.InvalidCredentialsError({
            message: "Invalid credentials",
          }),
        );
      }

      return user;
    }),
);

/**
 * Create a resolver for password hashing
 */
export const makeHashPasswordResolver = RequestResolver.fromEffect(
  (request: Requests.HashPasswordRequest) =>
    Effect.gen(function* () {
      const passwordHasher = yield* PasswordHasherTag;
      return yield* passwordHasher.hash(request.password);
    }),
);

/**
 * Create a resolver for password verification
 */
export const makeVerifyPasswordResolver = RequestResolver.fromEffect(
  (request: Requests.VerifyPasswordRequest) =>
    Effect.gen(function* () {
      const passwordHasher = yield* PasswordHasherTag;
      return yield* passwordHasher.verify(request.password, request.hash);
    }),
);

/**
 * Resolver for SignUpEmailRequest
 */
export const signUpEmailResolver = RequestResolver.makeBatched(
  (requests: Array<Requests.SignUpEmailRequest>) =>
    Effect.forEach(requests, (request) =>
      Effect.gen(function* () {
        const authLifecycle = yield* AuthLifecycleServiceTag;
        return yield* authLifecycle.signUp(request.input);
      }),
    ),
);

/**
 * Resolver for SignInEmailRequest
 */
export const signInEmailResolver = RequestResolver.makeBatched(
  (requests: Array<Requests.SignInEmailRequest>) =>
    Effect.forEach(requests, (request) =>
      Effect.gen(function* () {
        const authLifecycle = yield* AuthLifecycleServiceTag;
        return yield* authLifecycle.signIn(request.input);
      }),
    ),
);

/**
 * Resolver for VerifyEmailRequest
 */
export const verifyEmailResolver = RequestResolver.makeBatched(
  (requests: Array<Requests.VerifyEmailRequest>) =>
    Effect.forEach(requests, (request) =>
      Effect.gen(function* () {
        const authLifecycle = yield* AuthLifecycleServiceTag;
        return yield* authLifecycle.verifyEmail(request.input);
      }),
    ),
);

/**
 * Resolver for RequestPasswordResetRequest
 */
export const makeRequestPasswordResetResolver = RequestResolver.fromEffect(
  (request: Requests.RequestPasswordResetRequest) =>
    Effect.gen(function* () {
      const passwordReset = yield* PasswordResetServiceTag;
      return yield* passwordReset.requestPasswordReset(request.email);
    }),
);

/**
 * Resolver for ResetPasswordRequest
 */
export const makeResetPasswordResolver = RequestResolver.fromEffect(
  (request: Requests.ResetPasswordRequest) =>
    Effect.gen(function* () {
      const passwordReset = yield* PasswordResetServiceTag;
      return yield* passwordReset.resetPassword(request.token, request.newPassword);
    }),
);

/**
 * Resolver for GetUserRequest
 */
export const makeGetUserResolver = RequestResolver.fromEffect((request: Requests.GetUserRequest) =>
  Effect.gen(function* () {
    const userService = yield* UserServiceTag;
    return yield* userService.getUser(request.userId);
  }),
);

/**
 * Resolver for GetUserByEmailRequest
 */
export const makeGetUserByEmailResolver = RequestResolver.fromEffect(
  (request: Requests.GetUserByEmailRequest) =>
    Effect.gen(function* () {
      const userService = yield* UserServiceTag;
      return yield* userService.getUserByEmail(request.email);
    }),
);

/**
 * Resolver for UpdateUserAttributesRequest
 */
export const makeUpdateUserAttributesResolver = RequestResolver.fromEffect(
  (request: Requests.UpdateUserAttributesRequest) =>
    Effect.gen(function* () {
      const userService = yield* UserServiceTag;
      return yield* userService.updateUserAttributes(request.userId, request.attributes);
    }),
);

/**
 * Resolver for MarkEmailVerifiedRequest
 */
export const makeMarkEmailVerifiedResolver = RequestResolver.fromEffect(
  (request: Requests.MarkEmailVerifiedRequest) =>
    Effect.gen(function* () {
      const userService = yield* UserServiceTag;
      return yield* userService.markEmailVerified(request.userId);
    }),
);

/**
 * Resolver for DeleteUserRequest
 */
export const makeDeleteUserResolver = RequestResolver.fromEffect(
  (request: Requests.DeleteUserRequest) =>
    Effect.gen(function* () {
      const userService = yield* UserServiceTag;
      return yield* userService.deleteUser(request.userId);
    }),
);
