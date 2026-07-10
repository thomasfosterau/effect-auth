import { Context, Effect, Layer } from "effect";
import * as Errors from "./Errors.ts";
import { normalizeEmail } from "./utils.ts";
import { Hooks, type HookError } from "./Hooks.ts";
import {
  EmailPasswordService,
  EmailPasswordStore,
  type SecondFactorChallenge,
  type SignInInput,
  type SignUpInput,
} from "./email/EmailPassword.ts";
import {
  type EmailVerificationResult,
  EmailVerificationService,
} from "./email/EmailVerification.ts";
import { SessionService } from "./session/SessionService.ts";
import { UserService } from "./User.ts";
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

export class AuthLifecycleService extends Context.Service<
  AuthLifecycleService,
  {
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
      | HookError
    >;

    readonly signIn: (
      input: SignInInput,
    ) => Effect.Effect<
      AuthLifecycleResult,
      | Errors.AuthError
      | Errors.HashingError
      | Errors.InvalidCredentialsError
      | Errors.EmailVerificationError
      | HookError
    >;

    readonly verifyEmail: (
      input: VerifyEmailInput,
    ) => Effect.Effect<
      AuthLifecycleResult,
      Errors.AuthError | Errors.EmailVerificationError | Errors.UserNotFoundError | HookError
    >;
  }
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
): Effect.Effect<
  typeof AuthLifecycleService.Service,
  never,
  | EmailPasswordService
  | EmailPasswordStore
  | SessionService
  | EmailVerificationService
  | UserService
  | Hooks
> =>
  Effect.gen(function* () {
    const requireEmailVerification = config.requireEmailVerification ?? false;
    const sendOnSignUp = config.sendOnSignUp ?? requireEmailVerification;
    const sendOnSignIn = config.sendOnSignIn ?? false;
    const autoSignInAfterVerification = config.autoSignInAfterVerification ?? true;

    // FIX 1: consume the app-configured EmailPasswordService from context
    // rather than reconstructing inline (which silently dropped disableSignUp,
    // minPasswordLength, maxPasswordLength, etc.).
    const emailPassword = yield* EmailPasswordService;
    const emailPasswordStore = yield* EmailPasswordStore;
    const verification = yield* EmailVerificationService;
    const userService = yield* UserService;
    const sessionManager = yield* SessionService;

    return {
      signUp: Effect.fn("AuthLifecycleService.signUp")(function* (input: SignUpInput) {
        // FIX 3: catch EmailInUseError to handle the atomicity gap — if
        // createVerification fails after the user+password are written, a retry
        // hits EmailInUseError for an unverified account. Re-issue the
        // verification token so the user can complete sign-up without needing
        // a support intervention.
        const outcome = yield* emailPassword.signUp(input).pipe(
          Effect.map((r) => ({ recovered: false as const, result: r })),
          Effect.catchTag("EmailInUseError", (e) =>
            Effect.gen(function* () {
              const existing = yield* emailPasswordStore.getUserByEmail(
                normalizeEmail(input.email),
              );

              if (!existing || existing.emailVerified) {
                return yield* Effect.fail(e);
              }

              // Unverified duplicate: resend (also invalidates stale tokens,
              // matching FIX 5 behaviour).
              const email = getEmailFromUser(existing);
              if (sendOnSignUp && email) {
                yield* verification.resendVerification(existing.id, email);
              }

              return { recovered: true as const, user: existing };
            }),
          ),
        );

        if (outcome.recovered) {
          return {
            user: outcome.user,
            needsEmailVerification: true,
          } satisfies AuthLifecycleResult;
        }

        const result = outcome.result;
        const email = getEmailFromUser(result.user);
        const needsEmailVerification = requireEmailVerification && !isEmailVerified(result.user);

        if (sendOnSignUp && needsEmailVerification && email) {
          yield* verification.createVerification(result.user.id, email);
        }

        return {
          user: result.user,
          ...(!needsEmailVerification &&
            result.session !== undefined && { session: result.session }),
          needsEmailVerification,
        } satisfies AuthLifecycleResult;
      }),

      signIn: Effect.fn("AuthLifecycleService.signIn")(function* (input: SignInInput) {
        const signInResult = yield* Effect.catchTag(
          emailPassword.signIn(input),
          "EmailNotVerifiedError",
          (error) =>
            Effect.gen(function* () {
              const user = yield* emailPasswordStore.getUserByEmail(error.email);

              if (!user) {
                return yield* Effect.fail(
                  new Errors.InvalidCredentialsError({
                    message: "Invalid email or password",
                  }),
                );
              }

              // FIX 5: use resendVerification (which invalidates prior tokens
              // via deleteByUserId) instead of createVerification.
              if (sendOnSignIn) {
                yield* verification.resendVerification(user.id, error.email);
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

      verifyEmail: Effect.fn("AuthLifecycleService.verifyEmail")(function* (
        input: VerifyEmailInput,
      ) {
        // FIX 4: peekToken validates and returns the record without burning it,
        // so a failure in markEmailVerified leaves the token valid for retry.
        const verificationRecord = yield* verification.peekToken(input.token);

        // FIX 2: reject if the token's email no longer matches the current user
        // — a stale token for a since-changed address must not verify the new one.
        const currentUser = yield* userService.getUser(verificationRecord.userId);
        if (normalizeEmail(verificationRecord.email) !== normalizeEmail(currentUser.email)) {
          return yield* Effect.fail(
            new Errors.EmailVerificationError({
              message: "Verification token is no longer valid for this email address",
            }),
          );
        }

        // FIX 4: durable state change BEFORE burning the token.
        const verifiedUser = yield* userService.markEmailVerified(verificationRecord.userId);

        // burnToken deletes the token and fires the afterVerifyEmail hook.
        const verificationResult = {
          userId: verificationRecord.userId,
          email: verificationRecord.email,
          verified: true,
        } satisfies EmailVerificationResult;
        yield* verification.burnToken(verificationRecord.token, verificationResult);

        if (!autoSignInAfterVerification) {
          return {
            user: verifiedUser,
            needsEmailVerification: false,
          } satisfies AuthLifecycleResult;
        }

        const session = yield* sessionManager.createSession(
          verificationRecord.userId,
          input.sessionAttributes,
        );

        return {
          user: verifiedUser,
          session,
          needsEmailVerification: false,
        } satisfies AuthLifecycleResult;
      }),
    };
  });
