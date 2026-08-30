/**
 * Unified delivery seams: {@link EmailSender} and {@link SMSSender}.
 *
 * Every message-sending feature in effect-auth takes its own delivery
 * callback (`EmailVerification.sendEmail`, `MagicLink.sendMagicLink`,
 * `EmailOTP.sendVerificationOTP`, `PhoneOTP.sendOTP`, ...). Those callbacks
 * remain the full-control escape hatch — but they give delivery adapters
 * (Resend, SES, Nodemailer, Twilio, ...) no single contract to implement.
 *
 * This module adds that contract: an adapter implements `EmailSender` and/or
 * `SMSSender` once, and {@link emailCallbacks} / {@link smsCallbacks} derive
 * every per-feature callback from it. The sender receives the recipient, a
 * stable {@link EmailMessage.purpose | purpose} tag, and the flow's
 * parameters (token, OTP code, ...), and renders/sends however it likes —
 * template selection is keyed off `purpose`.
 *
 * ```ts
 * const sender = yield* EmailSender; // provided by an adapter package
 * const send = emailCallbacks(sender, yield* IdentifierStore);
 *
 * MagicLinkService.layer({ sendMagicLink: send.sendMagicLink, ... })
 * EmailVerificationService.layer({ sendEmail: send.sendVerificationEmail, ... })
 * ```
 *
 * @module delivery
 */
import { Context, Effect } from "effect";
import * as Errors from "./Errors.ts";
import type * as Types from "./Types.ts";
import type { EmailOTPPurpose } from "./email/EmailOTP.ts";
import type { PhoneOTPPurpose } from "./PhoneOTP.ts";
import { anyEmailValue, type IdentifierStore } from "./Identifier.ts";
import { getPhoneNumber } from "./PhoneOTP.ts";

// ---------------------------------------------------------------------------
// Messages
// ---------------------------------------------------------------------------

/**
 * Stable purpose tags for the messages effect-auth sends. Adapters key
 * template selection off this value. Extensible: app code may send its own
 * purposes through the same sender.
 */
export type DeliveryPurpose =
  | "email-verification"
  | "magic-link"
  | `email-otp:${EmailOTPPurpose}`
  | "password-reset"
  | "change-email"
  | "delete-account"
  | `phone-otp:${PhoneOTPPurpose}`
  | "second-factor-otp"
  | (string & {});

/** An email to deliver. `params` carries the flow's payload (token, otp, ...). */
export interface EmailMessage {
  readonly to: string;
  readonly purpose: DeliveryPurpose;
  readonly params: Readonly<Record<string, string>>;
}

/** An SMS to deliver. `to` is the phone number as stored (normalize upstream). */
export interface SMSMessage {
  readonly to: string;
  readonly purpose: DeliveryPurpose;
  readonly params: Readonly<Record<string, string>>;
}

// ---------------------------------------------------------------------------
// Sender services
// ---------------------------------------------------------------------------

/**
 * The single contract an email-delivery adapter implements. Failures are
 * `AuthError` with the underlying provider error as `cause`.
 */
export class EmailSender extends Context.Service<
  EmailSender,
  {
    readonly send: (message: EmailMessage) => Effect.Effect<void, Errors.AuthError>;
  }
>()("@effect-auth/EmailSender") {}

/** The single contract an SMS-delivery adapter implements. */
export class SMSSender extends Context.Service<
  SMSSender,
  {
    readonly send: (message: SMSMessage) => Effect.Effect<void, Errors.AuthError>;
  }
>()("@effect-auth/SMSSender") {}

// ---------------------------------------------------------------------------
// Per-feature callback derivation
// ---------------------------------------------------------------------------

/**
 * Derive every email-based per-feature delivery callback from an
 * {@link EmailSender}. Each property matches the corresponding feature
 * config's callback signature (and error type) exactly, so wiring is
 * one-line per feature.
 */
export const emailCallbacks = (
  sender: typeof EmailSender.Service,
  identifiers: typeof IdentifierStore.Service,
) => ({
  /** `EmailVerificationConfig.sendEmail` */
  sendVerificationEmail: (to: string, token: string) =>
    sender.send({ to, purpose: "email-verification", params: { token } }).pipe(
      Effect.mapError(
        (cause) =>
          new Errors.EmailVerificationError({
            message: "Failed to send verification email",
            cause,
          }),
      ),
    ),

  /** `MagicLinkConfig.sendMagicLink` */
  sendMagicLink: (email: string, token: string) =>
    sender
      .send({ to: email, purpose: "magic-link", params: { token } })
      .pipe(
        Effect.mapError(
          (cause) => new Errors.MagicLinkError({ message: "Failed to send magic link", cause }),
        ),
      ),

  /** `EmailOTPConfig.sendVerificationOTP` */
  sendVerificationOTP: (email: string, otp: string, purpose: EmailOTPPurpose) =>
    sender.send({ to: email, purpose: `email-otp:${purpose}`, params: { otp } }),

  /** `PasswordResetConfig.sendResetPassword` */
  sendResetPassword: (email: string, token: string) =>
    sender
      .send({ to: email, purpose: "password-reset", params: { token } })
      .pipe(
        Effect.mapError(
          (cause) =>
            new Errors.PasswordResetError({ message: "Failed to send reset email", cause }),
        ),
      ),

  /** `AccountManagementConfig.sendChangeEmailVerification` (sent to the NEW address) */
  sendChangeEmailVerification: (params: {
    readonly user: Types.User;
    readonly newEmail: string;
    readonly token: string;
  }) =>
    sender.send({
      to: params.newEmail,
      purpose: "change-email",
      params: { token: params.token },
    }),

  /** `AccountManagementConfig.sendDeleteAccountVerification` */
  sendDeleteAccountVerification: (params: {
    readonly user: Types.User;
    readonly email: string | null;
    readonly token: string;
  }) =>
    params.email === null
      ? Effect.fail(
          new Errors.AuthError({ message: "User has no email for account-deletion delivery" }),
        )
      : sender.send({
          to: params.email,
          purpose: "delete-account",
          params: { token: params.token },
        }),

  /** `OTPSecondFactorConfig.sendOTP`, delivering the code to the user's email identifier. */
  sendSecondFactorOTP: (user: Types.User, otp: string) =>
    Effect.gen(function* () {
      const email = anyEmailValue(yield* identifiers.listByUser(user.id));
      if (email === null) {
        return yield* Effect.fail(
          new Errors.AuthError({ message: "User has no email for second-factor OTP" }),
        );
      }
      yield* sender.send({ to: email, purpose: "second-factor-otp", params: { otp } });
    }),
});

/**
 * Derive the SMS-based per-feature delivery callbacks from an
 * {@link SMSSender}.
 */
export const smsCallbacks = (
  sender: typeof SMSSender.Service,
  identifiers: typeof IdentifierStore.Service,
) => ({
  /** `PhoneOTPConfig.sendOTP` */
  sendPhoneOTP: (phoneNumber: string, otp: string, purpose: PhoneOTPPurpose) =>
    sender.send({ to: phoneNumber, purpose: `phone-otp:${purpose}`, params: { otp } }),

  /**
   * `OTPSecondFactorConfig.sendOTP`, delivering the code to the user's
   * `phone` identifier. Fails with `AuthError` when the user has no phone
   * number on file.
   */
  sendSecondFactorOTP: (user: Types.User, otp: string) =>
    Effect.gen(function* () {
      const phoneNumber = yield* getPhoneNumber(identifiers, user.id);
      if (phoneNumber === null) {
        return yield* Effect.fail(
          new Errors.AuthError({ message: "User has no phone number for second-factor OTP" }),
        );
      }
      yield* sender.send({ to: phoneNumber, purpose: "second-factor-otp", params: { otp } });
    }),
});
