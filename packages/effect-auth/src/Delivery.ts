/**
 * Unified delivery seams: {@link EmailSender} and {@link SmsSender}.
 *
 * Every message-sending feature in effect-auth takes its own delivery
 * callback (`EmailVerification.sendEmail`, `MagicLink.sendMagicLink`,
 * `EmailOtp.sendVerificationOtp`, `PhoneOtp.sendOtp`, ...). Those callbacks
 * remain the full-control escape hatch — but they give delivery adapters
 * (Resend, SES, Nodemailer, Twilio, ...) no single contract to implement.
 *
 * This module adds that contract: an adapter implements `EmailSender` and/or
 * `SmsSender` once, and {@link emailCallbacks} / {@link smsCallbacks} derive
 * every per-feature callback from it. The sender receives the recipient, a
 * stable {@link EmailMessage.purpose | purpose} tag, and the flow's
 * parameters (token, OTP code, ...), and renders/sends however it likes —
 * template selection is keyed off `purpose`.
 *
 * ```ts
 * import assert from "node:assert/strict"
 * import { Effect, Layer, Queue } from "effect"
 * import {
 *   EmailSender,
 *   emailCallbacks,
 *   IdentifierStore,
 *   memoryIdentifierStore,
 *   type EmailMessage,
 * } from "@thomasfosterau/effect-auth"
 *
 * // An in-memory adapter: every message is put on an outbox the program reads.
 * const outbox = Effect.runSync(Queue.unbounded<EmailMessage>())
 * const adapter = Layer.succeed(EmailSender, {
 *   send: (message) => Queue.offer(outbox, message).pipe(Effect.asVoid),
 * })
 *
 * const program = Effect.gen(function* () {
 *   // An adapter (Resend, SES, ...) implements EmailSender once; the per-feature
 *   // callbacks are derived from it.
 *   const sender = yield* EmailSender // provided by an adapter package
 *   const send = emailCallbacks(sender, yield* IdentifierStore)
 *
 *   yield* send.sendMagicLink("ada@example.com", "magic-token")
 *   yield* send.sendVerificationEmail("ada@example.com", "verify-token")
 *
 *   // Delivery is dispatched off the response path, so read the two messages back.
 *   const messages = [yield* Queue.take(outbox), yield* Queue.take(outbox)]
 *   assert.deepEqual(
 *     messages.find((m) => m.purpose === "magic-link"),
 *     { to: "ada@example.com", purpose: "magic-link", params: { token: "magic-token" } },
 *   )
 *   assert.deepEqual(
 *     messages.find((m) => m.purpose === "email-verification"),
 *     { to: "ada@example.com", purpose: "email-verification", params: { token: "verify-token" } },
 *   )
 * }).pipe(
 *   Effect.provide(
 *     Layer.mergeAll(adapter, Layer.succeed(IdentifierStore, memoryIdentifierStore())),
 *   ),
 * )
 *
 * await Effect.runPromise(program)
 * ```
 *
 * @module delivery
 */
import { Context, Effect } from "effect";
import * as Errors from "./Errors.ts";
import * as Obs from "./Observability.ts";
import type * as Types from "./Types.ts";
import type { EmailOtpPurpose } from "./email/EmailOtp.ts";
import type { PhoneOtpPurpose } from "./PhoneOtp.ts";
import { anyEmailValue, type IdentifierStore } from "./Identifier.ts";
import { getPhoneNumber } from "./PhoneOtp.ts";

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
  | "existing-account"
  | "magic-link"
  | `email-otp:${EmailOtpPurpose}`
  | "password-reset"
  | "change-email"
  | "delete-account"
  | `phone-otp:${PhoneOtpPurpose}`
  | "second-factor-otp"
  | (string & {});

/** An email to deliver. `params` carries the flow's payload (token, otp, ...). */
export interface EmailMessage {
  readonly to: string;
  readonly purpose: DeliveryPurpose;
  readonly params: Readonly<Record<string, string>>;
}

/** An SMS to deliver. `to` is the phone number as stored (normalize upstream). */
export interface SmsMessage {
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
export class SmsSender extends Context.Service<
  SmsSender,
  {
    readonly send: (message: SmsMessage) => Effect.Effect<void, Errors.AuthError>;
  }
>()("@effect-auth/SmsSender") {}

// ---------------------------------------------------------------------------
// Off-response-path dispatch
// ---------------------------------------------------------------------------

/**
 * Dispatch a send on its own detached fiber instead of awaiting it inline.
 *
 * Every delivery flow (verification email, magic link, OTP, ...) sends on
 * only one of its branches — e.g. sign-up's fresh-registration branch mails
 * a token, its duplicate-registration branch does not. Awaiting the vendor
 * round-trip inline before answering the caller makes that difference in
 * work itself a timing oracle, exactly the asymmetry `EmailPasswordConfig`'s
 * `antiEnumeration` mode closes at the response-body level. `forkDetach`
 * (rather than `forkChild`) is required here: a child fiber is interrupted
 * when its parent — the request's fiber — completes, which for a
 * `Effect.sync`-only test double happens before the fiber is even
 * scheduled; a detached fiber outlives the request and actually finishes
 * the send.
 *
 * The outcome is never surfaced to the caller — a failed send must not fail
 * the flow that triggered it — so it is logged and counted here instead;
 * that log/metric pair is the only place a failed send is observable.
 */
const dispatch = <E>(purpose: DeliveryPurpose, send: Effect.Effect<void, E>): Effect.Effect<void> =>
  send.pipe(
    Effect.tap(() => Obs.recordDeliverySend(purpose, "success")),
    Effect.tapError((cause) =>
      Effect.logError("[effect-auth] delivery send failed", { purpose, cause }).pipe(
        Effect.andThen(Obs.recordDeliverySend(purpose, "failure")),
      ),
    ),
    Effect.ignore,
    Effect.forkDetach,
    Effect.asVoid,
  );

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
    dispatch(
      "email-verification",
      sender.send({ to, purpose: "email-verification", params: { token } }),
    ),

  /**
   * `AuthLifecycleConfig.sendExistingAccountNotice`: tells an address's holder
   * that someone tried to sign up with it. It carries no token, so `params`
   * is empty.
   */
  sendExistingAccountNotice: (to: string) =>
    dispatch("existing-account", sender.send({ to, purpose: "existing-account", params: {} })),

  /** `MagicLinkConfig.sendMagicLink` */
  sendMagicLink: (email: string, token: string) =>
    dispatch("magic-link", sender.send({ to: email, purpose: "magic-link", params: { token } })),

  /** `EmailOtpConfig.sendVerificationOtp` */
  sendVerificationOtp: (email: string, otp: string, purpose: EmailOtpPurpose) =>
    dispatch(
      `email-otp:${purpose}`,
      sender.send({ to: email, purpose: `email-otp:${purpose}`, params: { otp } }),
    ),

  /** `PasswordResetConfig.sendResetPassword` */
  sendResetPassword: (email: string, token: string) =>
    dispatch(
      "password-reset",
      sender.send({ to: email, purpose: "password-reset", params: { token } }),
    ),

  /** `AccountManagementConfig.sendChangeEmailVerification` (sent to the NEW address) */
  sendChangeEmailVerification: (params: {
    readonly user: Types.User;
    readonly newEmail: string;
    readonly token: string;
  }) =>
    dispatch(
      "change-email",
      sender.send({
        to: params.newEmail,
        purpose: "change-email",
        params: { token: params.token },
      }),
    ),

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
      : dispatch(
          "delete-account",
          sender.send({
            to: params.email,
            purpose: "delete-account",
            params: { token: params.token },
          }),
        ),

  /** `OtpSecondFactorConfig.sendOtp`, delivering the code to the user's email identifier. */
  sendSecondFactorOtp: (user: Types.User, otp: string) =>
    Effect.gen(function* () {
      const email = anyEmailValue(yield* identifiers.listByUser(user.id));
      if (email === null) {
        return yield* new Errors.AuthError({ message: "User has no email for second-factor OTP" });
      }
      yield* dispatch(
        "second-factor-otp",
        sender.send({ to: email, purpose: "second-factor-otp", params: { otp } }),
      );
    }),
});

/**
 * Derive the SMS-based per-feature delivery callbacks from an
 * {@link SmsSender}.
 */
export const smsCallbacks = (
  sender: typeof SmsSender.Service,
  identifiers: typeof IdentifierStore.Service,
) => ({
  /** `PhoneOtpConfig.sendOtp` */
  sendPhoneOtp: (phoneNumber: string, otp: string, purpose: PhoneOtpPurpose) =>
    dispatch(
      `phone-otp:${purpose}`,
      sender.send({ to: phoneNumber, purpose: `phone-otp:${purpose}`, params: { otp } }),
    ),

  /**
   * `OtpSecondFactorConfig.sendOtp`, delivering the code to the user's
   * `phone` identifier. Fails with `AuthError` when the user has no phone
   * number on file.
   */
  sendSecondFactorOtp: (user: Types.User, otp: string) =>
    Effect.gen(function* () {
      const phoneNumber = yield* getPhoneNumber(identifiers, user.id);
      if (phoneNumber === null) {
        return yield* new Errors.AuthError({
          message: "User has no phone number for second-factor OTP",
        });
      }
      yield* dispatch(
        "second-factor-otp",
        sender.send({ to: phoneNumber, purpose: "second-factor-otp", params: { otp } }),
      );
    }),
});
