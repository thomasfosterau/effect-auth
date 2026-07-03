import { Context, Effect, Layer } from "effect";
import * as Errors from "./Errors.js";
import { Hooks, type HookError } from "./Hooks.js";
import {
  EmailPasswordStoreTag,
  type SecondFactorChallenge,
  type SignInInput,
  type SignUpInput,
  makeEmailPasswordService,
} from "./EmailPassword.js";
import { EmailVerificationServiceTag, EmailVerificationStoreTag } from "./EmailVerification.js";
import { PasswordHasherTag } from "./Password.js";
import { SessionManagerTag } from "./Session.js";
import { UserServiceStoreTag, UserServiceTag } from "./User.js";
import type * as Types from "./Types.js";

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
}

export interface VerifyEmailInput {
  readonly token: string;
  readonly sessionAttributes?: Record<string, unknown>;
}

export interface AuthLifecycleService {
  readonly signUp: (
    input: SignUpInput,
  ) => Effect.Effect<
    AuthLifecycleResult,
    | Errors.AuthError
    | Errors.EmailInUseError
    | Errors.HashingError
    | Errors.EmailVerificationError
    | Errors.EmailNotVerifiedError
    | HookError,
    | EmailPasswordStoreTag
    | PasswordHasherTag
    | SessionManagerTag
    | EmailVerificationServiceTag
    | EmailVerificationStoreTag
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
    | EmailPasswordStoreTag
    | PasswordHasherTag
    | SessionManagerTag
    | EmailVerificationServiceTag
    | EmailVerificationStoreTag
    | Hooks
  >;

  readonly verifyEmail: (
    input: VerifyEmailInput,
  ) => Effect.Effect<
    AuthLifecycleResult,
    Errors.AuthError | Errors.EmailVerificationError | Errors.UserNotFoundError | HookError,
    | UserServiceTag
    | UserServiceStoreTag
    | SessionManagerTag
    | EmailVerificationServiceTag
    | EmailVerificationStoreTag
    | Hooks
  >;
}

export class AuthLifecycleServiceTag extends Context.Service<
  AuthLifecycleServiceTag,
  AuthLifecycleService
>()("@effect-auth/AuthLifecycleService") {
  /**
   * Construct a Layer providing this service — the canonical form of
   * {@link AuthLifecycleServiceLayer}.
   */
  static readonly layer = (config: AuthLifecycleConfig = {}) => AuthLifecycleServiceLayer(config);
}

export const AuthLifecycleService = AuthLifecycleServiceTag;

const normalizeEmail = (email: string): string => email.trim().toLowerCase();

const getEmailFromUser = (user: Types.User): string | undefined =>
  user.email.length > 0 ? normalizeEmail(user.email) : undefined;

const isEmailVerified = (user: Types.User): boolean => user.emailVerified;

export const makeAuthLifecycleService = (
  config: AuthLifecycleConfig = {},
): Effect.Effect<AuthLifecycleService, never> => {
  const requireEmailVerification = config.requireEmailVerification ?? false;
  const sendOnSignUp = config.sendOnSignUp ?? requireEmailVerification;
  const sendOnSignIn = config.sendOnSignIn ?? false;
  const autoSignInAfterVerification = config.autoSignInAfterVerification ?? true;

  return Effect.sync(
    (): AuthLifecycleService => ({
      signUp: (input) =>
        Effect.gen(function* () {
          const emailPassword = yield* makeEmailPasswordService({
            requireEmailVerification,
            autoSignIn: true,
          });
          const verification = yield* EmailVerificationServiceTag;

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
          const verification = yield* EmailVerificationServiceTag;

          const signInResult = yield* Effect.catchTag(
            emailPassword.signIn(input),
            "EmailNotVerifiedError",
            (error) =>
              Effect.gen(function* () {
                const store = yield* EmailPasswordStoreTag;
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
          } satisfies AuthLifecycleResult;
        }),

      verifyEmail: (input) =>
        Effect.gen(function* () {
          const verification = yield* EmailVerificationServiceTag;
          const userService = yield* UserServiceTag;
          const sessionManager = yield* SessionManagerTag;

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

export const AuthLifecycleServiceLayer = (config: AuthLifecycleConfig = {}) =>
  Layer.effect(AuthLifecycleServiceTag, makeAuthLifecycleService(config));
