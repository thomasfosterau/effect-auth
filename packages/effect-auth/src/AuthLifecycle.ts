import { Context, Effect, Layer } from "effect";
import * as Errors from "./Errors.ts";
import { normalizeEmail } from "./utils.ts";
import { Hooks, type HookError } from "./Hooks.ts";
import {
  answeredByStandIn,
  EmailPasswordService,
  type SecondFactorChallenge,
  type SignInInput,
  type SignUpInput,
} from "./email/EmailPassword.ts";
import { IdentifierStore, type IdentifierType } from "./Identifier.ts";
import { UserStore } from "./UserStore.ts";
import {
  type EmailVerificationResult,
  EmailVerificationService,
} from "./email/EmailVerification.ts";
import { SessionService } from "./SessionService.ts";
import { UserService } from "./User.ts";
import type * as Types from "./Types.ts";

/**
 * Configuration for {@link AuthLifecycleService}.
 *
 * The stand-in check that picks the existing-account notice over the
 * verification send (`answeredByStandIn`, in `email/EmailPassword.ts`) assumes
 * read-your-writes: the identifier store must show a fresh sign-up's
 * just-claimed address, or, if it lags, the user store must show the fresh
 * user. A store that lags on both can send a fresh sign-up the notice instead
 * of its verification link.
 */
export interface AuthLifecycleConfig {
  readonly requireEmailVerification?: boolean;
  readonly sendOnSignUp?: boolean;
  readonly sendOnSignIn?: boolean;
  readonly autoSignInAfterVerification?: boolean;
  /**
   * Sends an address's holder a notice that someone tried to sign up with
   * it, in place of the verification email a fresh sign-up gets, when
   * `EmailPasswordConfig.antiEnumeration` answers a sign-up for an address
   * another user holds. `emailCallbacks(...).sendExistingAccountNotice` in
   * `Delivery.ts` derives it from an `EmailSender` (purpose
   * `"existing-account"`).
   *
   * That sign-up is answered by a stand-in user that no row backs, so a
   * verification link would be one the address's holder can never use.
   * `signUp` therefore stores no verification record for it, runs no
   * verification hooks, and sends this notice in place of the link. It sends
   * only where a fresh sign-up sends a verification email
   * (`requireEmailVerification`, with `sendOnSignUp` left on), so each of the
   * two answers makes one send. A failed notice fails the sign-up with the
   * same `EmailVerificationError` a failed verification send does.
   *
   * Pair the notice with the verification send on one transport, ideally both
   * derived from `emailCallbacks`. Those sends go through the same detached
   * dispatch, so neither puts a vendor round-trip on the response path, and a
   * failed send is logged and counted rather than answered. Hand-written
   * callbacks that await their vendor put one round-trip on each answer's
   * response path.
   *
   * Unset, such a sign-up sends nothing. With the notice unset and an inline
   * `sendEmail`, a vendor outage answers `500` for a fresh sign-up (its
   * verification send fails) and `200` for a held address (nothing is sent).
   * Likewise, a notice that fails where the verification send does not (for
   * example a renderer with no `"existing-account"` case) answers `500` for
   * held addresses only. When the notice is set, each answer makes one send,
   * so an awaited `sendEmail` costs both answers one round-trip each.
   *
   * `beforeCreateVerification` and `afterCreateVerification`, and anything
   * they enforce (throttling, captcha, bans), apply only to the fresh branch's
   * verification send. The notice is sent without them.
   */
  readonly sendExistingAccountNotice?:
    | ((email: string) => Effect.Effect<void, Errors.AuthError | Errors.EmailVerificationError>)
    | undefined;
}

/**
 * Outcome of a sign-up or sign-in through {@link AuthLifecycleService}.
 */
export interface AuthLifecycleResult {
  readonly user: Types.User;
  /**
   * The login handle a sign-up was made with: the email address it claimed;
   * under `antiEnumeration`, the address another user holds; or, with
   * `antiEnumeration` off, the address an existing user holds unverified,
   * which `signUp` answers with that user instead of failing (re-issuing its
   * verification when `sendOnSignUp` is set). Set by `signUp`, whose address is
   * always unverified at this point; the HTTP sign-up response reports the
   * user's `email` from it.
   */
  readonly identifier?: { readonly type: IdentifierType; readonly value: string } | undefined;
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

/**
 * Input to {@link AuthLifecycleService.verifyEmail}: the verification token and the attributes for the session it may issue.
 */
export interface VerifyEmailInput {
  readonly token: string;
  readonly sessionAttributes?: Record<string, unknown>;
}

/**
 * Email-and-password sign-up and sign-in orchestrated with email verification: sends verification emails, gates sign-in on a verified address when configured, and can sign the user in on verification.
 *
 * Requires `EmailPasswordService`, `EmailVerificationService`, `SessionService`, `UserService`, `UserStore`, `IdentifierStore` and `Hooks`.
 */
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
    Layer.effect(AuthLifecycleService, make(config));
}

export const make = (
  config: AuthLifecycleConfig = {},
): Effect.Effect<
  typeof AuthLifecycleService.Service,
  never,
  | EmailPasswordService
  | IdentifierStore
  | UserStore
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
    const identifiers = yield* IdentifierStore;
    const userStore = yield* UserStore;
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
              const identifier = yield* identifiers.getByValue(
                "email",
                normalizeEmail(input.email),
              );
              const existing = identifier === null ? null : yield* userStore.get(identifier.userId);

              if (!identifier || !existing || identifier.verified) {
                return yield* e;
              }

              // Unverified duplicate: resend (also invalidates stale tokens,
              // matching FIX 5 behaviour).
              if (sendOnSignUp) {
                yield* verification.resendVerification(existing.id, identifier.value);
              }

              return {
                recovered: true as const,
                user: existing,
                identifier: { type: "email" as const, value: identifier.value },
              };
            }),
          ),
        );

        if (outcome.recovered) {
          return {
            user: outcome.user,
            identifier: outcome.identifier,
            needsEmailVerification: true,
          } satisfies AuthLifecycleResult;
        }

        const result = outcome.result;
        const email = result.identifier?.value;
        // A freshly claimed email identifier is always unverified.
        const needsEmailVerification = requireEmailVerification;

        if (sendOnSignUp && needsEmailVerification && email !== undefined) {
          // Under anti-enumeration, an address another user holds is answered
          // by a stand-in no row backs: a verification record for it would
          // point at no user, and its link would reach the address's holder
          // and never verify. That holder gets the existing-account notice
          // instead, so each answer makes one send, and a failed notice fails
          // as a failed verification send does.
          if (yield* answeredByStandIn(identifiers, userStore, result, input.email)) {
            if (config.sendExistingAccountNotice !== undefined) {
              yield* config.sendExistingAccountNotice(email).pipe(
                Effect.mapError(
                  (cause) =>
                    new Errors.EmailVerificationError({
                      message: `Failed to send verification email to ${email}`,
                      cause,
                    }),
                ),
              );
            }
          } else {
            yield* verification.createVerification(result.user.id, email);
          }
        }

        return {
          user: result.user,
          ...(result.identifier !== undefined && { identifier: result.identifier }),
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
              const identifier = yield* identifiers.getByValue("email", error.email);
              const user = identifier === null ? null : yield* userStore.get(identifier.userId);

              if (!user) {
                return yield* new Errors.InvalidCredentialsError({
                  message: "Invalid email or password",
                });
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
        // so a failure in setVerified leaves the token valid for retry.
        const verificationRecord = yield* verification.peekToken(input.token);

        // FIX 2: reject unless the token's email is still one of this user's
        // identifiers — a stale token for a since-removed address must not
        // verify anything.
        const tokenEmail = normalizeEmail(verificationRecord.email);
        const identifier = yield* identifiers.getByValue("email", tokenEmail);
        if (identifier === null || identifier.userId !== verificationRecord.userId) {
          return yield* new Errors.EmailVerificationError({
            message: "Verification token is no longer valid for this email address",
          });
        }

        // FIX 4: durable state change BEFORE burning the token.
        yield* identifiers.setVerified(identifier.id, new Date());
        const verifiedUser = yield* userService.getUser(verificationRecord.userId);

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
