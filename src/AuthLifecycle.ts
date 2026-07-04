import { Context, Effect, Layer } from "effect";
import * as Errors from "./Errors.ts";
import { normalizeEmail } from "./utils.ts";
import { Hooks, type HookError } from "./Hooks.ts";
import {
  EmailPasswordStore,
  type SecondFactorChallenge,
  type SignInInput,
  type SignUpInput,
  makeEmailPasswordService,
} from "./EmailPassword.ts";
import { EmailVerificationService, EmailVerificationStore } from "./EmailVerification.ts";
import { PasswordHasher } from "./Password.ts";
import { SessionManager } from "./Session.ts";
import { UserServiceStore, UserService } from "./User.ts";
import type * as Types from "./Types.ts";

export interface AuthLifecycleConfig {
  readonly requireEmailVerification?: boolean;
  readonly sendOnSignUp?: boolean;
  readonly sendOnSignIn?: boolean;
  readonly autoSignInAfterVerification?: boolean;
}

export interface AuthLifecycleResult {
  readonly user: Types.User;
  readonly session?: Types.Session;
  readonly needsEmailVerification: boolean;
  /** Present when a second factor is required to complete sign-in. */
  readonly secondFactor?: SecondFactorChallenge;
  /**
   * Propagated from `SignInInput.rememberMe`. When `false`, the HTTP layer
   * emits a browser-session cookie (no `Max-Age`/`Expires`).
   */
  readonly rememberMe?: boolean;
}

export interface VerifyEmailInput {
  readonly token: string;
  readonly sessionAttributes?: Record<string, unknown>;
}

export interface AuthLifecycleServiceShape {
  readonly signUp: (
    input: SignUpInput,
  ) => Effect.Effect<
    AuthLifecycleResult,
    | Errors.AuthError
    | Errors.EmailInUseError
    | Errors.HashingError
    | Errors.EmailVerificationError
    | Errors.EmailNotVerifiedError
    | Errors.PasswordPolicyError
    | Errors.SignUpDisabledError
    | Errors.InvalidInputError
    | HookError,
    | EmailPasswordStore
    | PasswordHasher
    | SessionManager
    | EmailVerificationService
    | EmailVerificationStore
    | Hooks
  >;

  readonly signIn: (
    input: SignInInput,
  ) => Effect.Effect<
    AuthLifecycleResult,
    | Errors.AuthError
    | Errors.HashingError
    | Errors.InvalidCredentialsError
    | Errors.EmailVerificationError
    | HookError,
    | EmailPasswordStore
    | PasswordHasher
    | SessionManager
    | EmailVerificationService
    | EmailVerificationStore
    | Hooks
  >;

  readonly verifyEmail: (
    input: VerifyEmailInput,
  ) => Effect.Effect<
    AuthLifecycleResult,
    Errors.AuthError | Errors.EmailVerificationError | Errors.UserNotFoundError | HookError,
    | UserService
    | UserServiceStore
    | SessionManager
    | EmailVerificationService
    | EmailVerificationStore
    | Hooks
  >;
}

export class AuthLifecycleService extends Context.Service<
  AuthLifecycleService,
  AuthLifecycleServiceShape
>()("@effect-auth/AuthLifecycleService") {
  /**
   * Construct a Layer providing this service.
   */
  static readonly layer = (config: AuthLifecycleConfig = {}) =>
    Layer.effect(AuthLifecycleService, makeAuthLifecycleService(config));
}

const getEmailFromUser = (user: Types.User): string | undefined =>
  user.email.length > 0 ? normalizeEmail(user.email) : undefined;

const isEmailVerified = (user: Types.User): boolean => user.emailVerified;

export const makeAuthLifecycleService = (
  config: AuthLifecycleConfig = {},
): Effect.Effect<AuthLifecycleServiceShape, never> => {
  const requireEmailVerification = config.requireEmailVerification ?? false;
  const sendOnSignUp = config.sendOnSignUp ?? requireEmailVerification;
  const sendOnSignIn = config.sendOnSignIn ?? false;
  const autoSignInAfterVerification = config.autoSignInAfterVerification ?? true;

  return Effect.sync(
    (): AuthLifecycleServiceShape => ({
      signUp: (input) =>
        Effect.gen(function* () {
          const emailPassword = yield* makeEmailPasswordService({
            requireEmailVerification,
            autoSignIn: true,
          });
          const verification = yield* EmailVerificationService;

          const result = yield* emailPassword.signUp(input);
          const email = getEmailFromUser(result.user);
          const needsEmailVerification = requireEmailVerification && !isEmailVerified(result.user);

          if (sendOnSignUp && needsEmailVerification && email) {
            yield* verification.createVerification(result.user.id, email);
          }

          return {
            user: result.user,
            ...(result.session !== undefined && { session: result.session }),
            needsEmailVerification,
          } satisfies AuthLifecycleResult;
        }),

      signIn: (input) =>
        Effect.gen(function* () {
          const emailPassword = yield* makeEmailPasswordService({
            requireEmailVerification,
            autoSignIn: true,
          });
          const verification = yield* EmailVerificationService;

          const signInResult = yield* Effect.catchTag(
            emailPassword.signIn(input),
            "EmailNotVerifiedError",
            (error) =>
              Effect.gen(function* () {
                const store = yield* EmailPasswordStore;
                const user = yield* store.getUserByEmail(error.email);

                if (!user) {
                  return yield* Effect.fail(
                    new Errors.InvalidCredentialsError({
                      message: "Invalid email or password",
                    }),
                  );
                }

                if (sendOnSignIn) {
                  yield* verification.createVerification(user.id, error.email);
                }

                return {
                  user,
                  needsEmailVerification: true,
                } satisfies AuthLifecycleResult;
              }),
          );

          if ("needsEmailVerification" in signInResult) {
            return signInResult;
          }

          return {
            user: signInResult.user,
            ...(signInResult.session !== undefined && { session: signInResult.session }),
            ...(signInResult.secondFactor !== undefined && {
              secondFactor: signInResult.secondFactor,
            }),
            needsEmailVerification: false,
            ...(signInResult.rememberMe !== undefined && { rememberMe: signInResult.rememberMe }),
          } satisfies AuthLifecycleResult;
        }),

      verifyEmail: (input) =>
        Effect.gen(function* () {
          const verification = yield* EmailVerificationService;
          const userService = yield* UserService;
          const sessionManager = yield* SessionManager;

          const verificationResult = yield* verification.verifyToken(input.token);
          const user = yield* userService.markEmailVerified(verificationResult.userId);

          if (!autoSignInAfterVerification) {
            return {
              user,
              needsEmailVerification: false,
            } satisfies AuthLifecycleResult;
          }

          const session = yield* sessionManager.createSession(
            verificationResult.userId,
            input.sessionAttributes,
          );

          return {
            user,
            session,
            needsEmailVerification: false,
          } satisfies AuthLifecycleResult;
        }),
    }),
  );
};
