/**
 * The flows that send something to an address, over WorkOS: email
 * verification, password reset and Magic Auth (WorkOS's emailed sign-in code,
 * served as the core's `EmailOtpService`). WorkOS sends each from its
 * dashboard templates, or, with `delivery: "app"`, the app sends the reset link
 * and the sign-in code through the core `EmailSender` on a detached fiber.
 *
 * @since 0.1.0
 */
import * as Clock from "effect/Clock";
import * as Effect from "effect/Effect";
import * as Layer from "effect/Layer";
import * as Option from "effect/Option";
import * as Schema from "effect/Schema";
import * as Auth from "@thomasfosterau/effect-auth";
import { MagicAuth, PasswordReset, UserEnvelope } from "./Schemas.ts";
import { WorkOSAuthenticate, WorkOSSessions } from "./Session.ts";
import { path, toAuthError, WorkOSClient, type WorkOSError } from "./WorkOS.ts";

const MINUTE = 60 * 1000;

/** A 4xx WorkOS answer: the caller's input was refused, not the service faulted. */
const refused = (error: WorkOSError): boolean =>
  error.status >= 400 && error.status < 500 && error.status !== 429;

type Reset = typeof Auth.Password.PasswordResetService.Service;
type Otp = typeof Auth.Email.EmailOtpService.Service;

/**
 * `delivery: "app"` without an `EmailSender` where the layer is built; the
 * layer dies with it.
 *
 * @since 0.1.0
 * @category errors
 */
export class DeliveryConfigError extends Schema.TaggedError<
  DeliveryConfigError,
  { readonly brand: unique symbol }
>()("DeliveryConfigError", {
  message: Schema.String,
}) {}

const invalidCode = () =>
  new Auth.Errors.EmailVerificationError({ message: "Invalid or expired code" });

const verifyInTwoSteps = () =>
  Effect.fail(
    new Auth.Errors.EmailVerificationError({
      message: "The WorkOS backend verifies in one step (verifyToken)",
    }),
  );

const invalidResetToken = () =>
  new Auth.Errors.PasswordResetError({ message: "Invalid or expired token" });

const onlySignIn = () =>
  new Auth.Email.EmailOtpError({ message: "WorkOS Magic Auth codes are for sign-in only" });

/** The core `EmailSender` when `delivery: "app"` needs one; the layer dies without it. */
const appSender = Effect.fn("WorkOS.appSender")(function* () {
  const workos = yield* WorkOSClient;
  if (workos.config.delivery !== "app") return undefined;
  const sender = yield* Effect.serviceOption(Auth.Delivery.EmailSender);
  if (Option.isNone(sender)) {
    return yield* Effect.die(
      new DeliveryConfigError({
        message: 'WorkOS `delivery: "app"` needs an EmailSender where the layer is built',
      }),
    );
  }
  return { sender: sender.value, detached: yield* Auth.DeliveryScheduler.makeDetachedSend };
});

/**
 * Parse a verification token, `<userId>:<code>`: the user's id (which every
 * sign-up answer names) and the code WorkOS emailed.
 *
 * @since 0.1.0
 * @category utils
 */
export const parseVerificationToken = (
  token: string,
): Option.Option<{ readonly userId: string; readonly code: string }> => {
  const at = token.lastIndexOf(":");
  if (at <= 0 || at === token.length - 1) return Option.none();
  return Option.some({ userId: token.slice(0, at), code: token.slice(at + 1) });
};

/**
 * The core `EmailVerificationService` over WorkOS's emailed verification
 * code. WorkOS keeps no link tokens, so the token `verifyToken` takes is
 * `<userId>:<code>` ({@link parseVerificationToken}), and `createVerification`
 * / `resendVerification` answer an empty `token`: WorkOS sends the code
 * itself. `peekToken` and `burnToken` (the core's two-step verify) are
 * refused.
 *
 * @since 0.1.0
 * @category layers
 */
export const emailVerificationLayer: Layer.Layer<
  Auth.Email.EmailVerificationService,
  never,
  WorkOSClient | Auth.Hooks.Hooks
> = Layer.effect(
  Auth.Email.EmailVerificationService,
  Effect.gen(function* () {
    const workos = yield* WorkOSClient;
    const hooks = yield* Auth.Hooks.Hooks;

    const send = Effect.fn("WorkOS.EmailVerification.send")(function* (
      rawUserId: string,
      rawEmail: string,
    ) {
      const args = yield* hooks.beforeCreateVerification({ userId: rawUserId, email: rawEmail });
      yield* workos
        .request({
          method: "POST",
          path: path`/user_management/users/${args.userId}/email_verification/send`,
          route: "/user_management/users/{id}/email_verification/send",
          body: {},
        })
        .pipe(
          Effect.mapError((error) =>
            refused(error)
              ? new Auth.Errors.EmailVerificationError({
                  message: "WorkOS refused to send the code",
                })
              : toAuthError(error),
          ),
        );
      yield* hooks.afterCreateVerification(args);
      // TODO(#900): WorkOS's verification codes are said to last 10 minutes;
      // the answer to `send` does not say.
      return { token: "", expiresAt: (yield* Clock.currentTimeMillis) + 10 * MINUTE };
    });

    const verifyToken = Effect.fn("WorkOS.EmailVerification.verifyToken")(function* (raw: string) {
      const { token } = yield* hooks.beforeVerifyEmail({ token: raw });
      const found = parseVerificationToken(token);
      if (Option.isNone(found)) return yield* invalidCode();
      const parsed = found.value;
      const { user } = yield* workos
        .request({
          method: "POST",
          path: path`/user_management/users/${parsed.userId}/email_verification/confirm`,
          route: "/user_management/users/{id}/email_verification/confirm",
          body: { code: parsed.code },
          schema: UserEnvelope,
        })
        .pipe(Effect.mapError((error) => (refused(error) ? invalidCode() : toAuthError(error))));
      return yield* hooks.afterVerifyEmail({
        userId: user.id,
        email: Auth.Normalize.normalizeEmail(user.email),
        verified: user.email_verified,
      });
    });

    return Auth.Email.EmailVerificationService.of({
      createVerification: send,
      resendVerification: send,
      verifyToken,
      peekToken: verifyInTwoSteps,
      burnToken: verifyInTwoSteps,
    });
  }),
);

/**
 * The core `PasswordResetService` over WorkOS. A request for an address
 * WorkOS does not know answers as one it does. A reset ends every WorkOS
 * session of the user, so a cookie an attacker holds stops working.
 *
 * @since 0.1.0
 * @category layers
 */
export const passwordResetLayer: Layer.Layer<
  Auth.Password.PasswordResetService,
  never,
  WorkOSClient | Auth.SessionService.SessionService | Auth.Hooks.Hooks
> = Layer.effect(
  Auth.Password.PasswordResetService,
  Effect.gen(function* () {
    const workos = yield* WorkOSClient;
    const sessions = yield* Auth.SessionService.SessionService;
    const hooks = yield* Auth.Hooks.Hooks;
    const app = yield* appSender();

    return Auth.Password.PasswordResetService.of({
      requestPasswordReset: Effect.fn("WorkOS.PasswordReset.requestPasswordReset")(function* (
        ...[rawEmail, options]: Parameters<Reset["requestPasswordReset"]>
      ) {
        const { email: hooked } = yield* hooks.beforeRequestPasswordReset({ email: rawEmail });
        const email = Auth.Normalize.normalizeEmail(hooked);
        yield* hooks.beforeSendCode({
          method: "password-reset",
          purpose: "password-reset",
          address: email,
          ...(options?.captchaToken !== undefined && { captchaToken: options.captchaToken }),
        });
        const reset = yield* workos
          .request({
            method: "POST",
            path: "/user_management/password_reset",
            route: "/user_management/password_reset",
            body: { email },
            schema: PasswordReset,
          })
          .pipe(
            Effect.map(Option.some),
            // An unknown address is answered as a known one.
            Effect.catchTag("WorkOSError", (error) =>
              refused(error) ? Effect.succeedNone : Effect.fail(toAuthError(error)),
            ),
          );
        if (app !== undefined && Option.isSome(reset)) {
          const token = reset.value.password_reset_token;
          if (token != null) {
            yield* app.detached(
              "password-reset",
              app.sender.send({
                to: email,
                purpose: "password-reset",
                params: {
                  token,
                  ...(reset.value.password_reset_url != null && {
                    url: reset.value.password_reset_url,
                  }),
                },
              }),
            );
          }
        }
        yield* hooks.afterRequestPasswordReset({ email });
      }),
      resetPassword: Effect.fn("WorkOS.PasswordReset.resetPassword")(function* (
        rawToken: string,
        rawPassword: string,
      ) {
        const { token, newPassword } = yield* hooks.beforeResetPassword({
          token: rawToken,
          newPassword: rawPassword,
        });
        const { user } = yield* workos
          .request({
            method: "POST",
            path: "/user_management/password_reset/confirm",
            route: "/user_management/password_reset/confirm",
            body: { token, new_password: newPassword },
            schema: UserEnvelope,
          })
          .pipe(
            Effect.mapError((error) =>
              !refused(error)
                ? toAuthError(error)
                : (error.code ?? "").includes("password")
                  ? new Auth.Errors.PasswordResetError({
                      message: "The password does not meet the WorkOS password policy",
                    })
                  : invalidResetToken(),
            ),
          );
        yield* sessions.invalidateUserSessions(user.id);
        return yield* hooks.afterResetPassword({
          userId: user.id,
          email: Auth.Normalize.normalizeEmail(user.email),
          reset: true,
        });
      }),
    });
  }),
);

/**
 * WorkOS Magic Auth as the core `EmailOtpService`: `send` creates the code
 * (`POST /user_management/magic_auth`), `signIn` is the `magic-auth:code`
 * grant. Only the `"sign-in"` purpose exists; `check` (verify without signing
 * in) is refused. WorkOS budgets the guesses at a code; the core's
 * `beforeAuthenticate` gate runs first, so the IP limit counts them too.
 *
 * @since 0.1.0
 * @category layers
 */
export const magicAuthLayer: Layer.Layer<
  Auth.Email.EmailOtpService,
  never,
  WorkOSClient | WorkOSSessions | WorkOSAuthenticate | Auth.Hooks.Hooks
> = Layer.effect(
  Auth.Email.EmailOtpService,
  Effect.gen(function* () {
    const workos = yield* WorkOSClient;
    const sessions = yield* WorkOSSessions;
    const { authenticate } = yield* WorkOSAuthenticate;
    const hooks = yield* Auth.Hooks.Hooks;
    const app = yield* appSender();

    return Auth.Email.EmailOtpService.of({
      send: Effect.fn("WorkOS.MagicAuth.send")(function* (
        ...[rawEmail, purpose, options]: Parameters<Otp["send"]>
      ) {
        if (purpose !== "sign-in") return yield* onlySignIn();
        const email = Auth.Normalize.normalizeEmail(rawEmail);
        yield* hooks.beforeSendCode({
          method: "email-otp",
          purpose,
          address: email,
          ...(options?.captchaToken !== undefined && { captchaToken: options.captchaToken }),
        });
        const created = yield* workos
          .request({
            method: "POST",
            path: "/user_management/magic_auth",
            route: "/user_management/magic_auth",
            body: { email },
            schema: MagicAuth,
          })
          .pipe(
            Effect.mapError((error) =>
              refused(error)
                ? new Auth.Email.EmailOtpError({ message: "WorkOS refused to send a code" })
                : toAuthError(error),
            ),
          );
        return yield* app === undefined || created.code == null
          ? Effect.void
          : app.detached(
              "email-otp:sign-in",
              app.sender.send({
                to: email,
                purpose: "email-otp:sign-in",
                params: { otp: created.code },
              }),
            );
      }),
      signIn: Effect.fn("WorkOS.MagicAuth.signIn")(function* (
        ...[rawEmail, otp, options]: Parameters<Otp["signIn"]>
      ) {
        const email = Auth.Normalize.normalizeEmail(rawEmail);
        yield* hooks.beforeAuthenticate({
          method: "email-otp",
          identifier: { type: "email", value: email },
        });
        const auth = yield* authenticate({
          grant_type: "urn:workos:oauth:grant-type:magic-auth:code",
          email,
          code: otp,
        }).pipe(
          Effect.mapError((error) =>
            refused(error)
              ? new Auth.Email.EmailOtpError({ message: "Invalid or expired code" })
              : toAuthError(error),
          ),
        );
        const issued = yield* sessions.issue(auth, options?.sessionAttributes);
        yield* hooks.afterSignIn({
          user: issued.user,
          identifier: { type: "email", value: email },
          session: issued.session,
          token: issued.token,
          method: "email-otp",
        });
        return { user: issued.user, session: issued.session, token: issued.token };
      }),
      check: () => Effect.fail(onlySignIn()),
    });
  }),
);
