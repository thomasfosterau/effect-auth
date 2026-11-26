/**
 * Delivery seams: an adapter implements {@link EmailSender} or {@link
 * SmsSender} once, or backs it with an effect-connect provider through
 * `layerConnect`, and {@link emailCallbacks} / {@link smsCallbacks} derive
 * every feature's send callback, keyed by a stable `purpose`. Each derived
 * callback awaits its send.
 *
 * @example One adapter, every callback
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
 *   // An adapter implements EmailSender once; the per-feature
 *   // callbacks are derived from it.
 *   const sender = yield* EmailSender // provided by an adapter package
 *   const send = emailCallbacks(sender, yield* IdentifierStore)
 *
 *   yield* send.sendMagicLink("ada@example.com", "magic-token")
 *   yield* send.sendVerificationEmail("ada@example.com", "verify-token")
 *
 *   // Each callback awaits its send, so both messages are on the outbox.
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
import { Context, Effect, Layer, Match } from "effect";
import * as Option from "effect/Option";
import * as Arr from "effect/Array";
import * as Connect from "@thomasfosterau/effect-connect";
import * as Errors from "./Errors.ts";
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
  | "email-change-requested"
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

/** The logging transports' one line per message: recipient and purpose, never `params`. */
const logUnsent = (
  channel: "email" | "sms",
  message: EmailMessage | SmsMessage,
): Effect.Effect<void> =>
  Effect.logWarning("[effect-auth] delivery not sent (logging transport)", {
    channel,
    to: message.to,
    purpose: message.purpose,
  });

// ---------------------------------------------------------------------------
// Default renderers
// ---------------------------------------------------------------------------

/** The content of an email: what a renderer turns a {@link EmailMessage} into. */
export interface RenderedEmail {
  readonly subject: string;
  readonly text?: string | undefined;
  readonly html?: string | undefined;
}

const emailSubject = (purpose: DeliveryPurpose): string =>
  Match.value(purpose).pipe(
    Match.when("email-verification", () => "Verify your email address"),
    Match.when("magic-link", () => "Your sign-in link"),
    Match.when("password-reset", () => "Reset your password"),
    Match.when("change-email", () => "Confirm your new email address"),
    Match.when("email-change-requested", () => "Your email address is being changed"),
    Match.when("delete-account", () => "Confirm account deletion"),
    Match.when("second-factor-otp", () => "Your verification code"),
    Match.when("existing-account", () => "Someone tried to sign up with your email address"),
    Match.orElse((other) =>
      other.startsWith("email-otp:") ? "Your verification code" : "Action required",
    ),
  );

const EXISTING_ACCOUNT_TEXT = [
  "Someone tried to create an account with this email address, but it already belongs to an account. Nothing about your account was changed.",
  "If this was you, sign in instead, or reset your password if you have forgotten it.",
  "If it wasn't you, you can ignore this email.",
].join("\n\n");

const emailChangeRequestedText = (newEmail: string | undefined): string =>
  [
    `Someone signed in to your account asked to change its email address${newEmail === undefined ? "" : ` to ${newEmail}`}. The change happens only once the new address is confirmed.`,
    "If this was you, there is nothing to do.",
    "If it wasn't you, sign in and change your password now, and sign out your other sessions.",
  ].join("\n\n");

/**
 * The built-in email renderer: a purpose-keyed subject and a plain-text body
 * carrying `params.otp`, then `params.url` (or, failing that,
 * `params.token`). The `"existing-account"` notice gets a fixed body pointing
 * at sign-in or password reset, and the `"email-change-requested"` notice one
 * naming `params.newEmail`. A functional fallback for tests and first
 * runs, not a template system: applications pass their own `render`.
 */
export const defaultEmailRender = (message: EmailMessage): RenderedEmail => {
  const subject = emailSubject(message.purpose);
  if (message.purpose === "existing-account") {
    return { subject, text: EXISTING_ACCOUNT_TEXT };
  }
  if (message.purpose === "email-change-requested") {
    return { subject, text: emailChangeRequestedText(message.params.newEmail) };
  }
  const { otp, token, url } = message.params;
  const lines: Array<string> = [];
  if (otp !== undefined) lines.push(`Your code: ${otp}`);
  if (url !== undefined) lines.push(`Continue here: ${url}`);
  else if (token !== undefined) lines.push(`Your token: ${token}`);
  return {
    subject,
    text: Arr.isReadonlyArrayNonEmpty(lines) ? lines.join("\n\n") : "Please continue in the app.",
  };
};

/**
 * The built-in SMS renderer: a purpose-keyed lead-in followed by
 * `params.otp` (or, failing that, `params.token`). A functional fallback;
 * applications pass their own `render`.
 */
export const defaultSmsRender = (message: SmsMessage): string => {
  const lead =
    message.purpose === "second-factor-otp" || message.purpose.startsWith("phone-otp:")
      ? "Your verification code"
      : "Message";
  const value = message.params.otp ?? message.params.token;
  return value !== undefined ? `${lead}: ${value}` : lead;
};

// ---------------------------------------------------------------------------
// effect-connect bridges
// ---------------------------------------------------------------------------

/** Configuration for {@link EmailSender.fromConnect} and {@link EmailSender.layerConnect}. */
export interface ConnectEmailSenderConfig {
  /** The sender every message goes out from. */
  readonly from: Connect.Recipient;
  /** Render a message's content. Defaults to {@link defaultEmailRender}. */
  readonly render?: ((message: EmailMessage) => RenderedEmail) | undefined;
}

/** Configuration for {@link SmsSender.fromConnect} and {@link SmsSender.layerConnect}. */
export interface ConnectSmsSenderConfig {
  /** The sender ID or number. Omitted, the provider's configured default is used. */
  readonly from?: string | undefined;
  /** Render a message's body. Defaults to {@link defaultSmsRender}. */
  readonly render?: ((message: SmsMessage) => string) | undefined;
}

const toConnectEmail = (
  message: EmailMessage,
  config: ConnectEmailSenderConfig,
): Connect.EmailMessage => {
  const { subject, text, html } = (config.render ?? defaultEmailRender)(message);
  return {
    from: config.from,
    to: [{ email: message.to }],
    subject,
    ...(text === undefined ? {} : { text }),
    ...(html === undefined ? {} : { html }),
  };
};

const toConnectSms = (message: SmsMessage, config: ConnectSmsSenderConfig): Connect.SmsMessage => ({
  to: message.to,
  body: (config.render ?? defaultSmsRender)(message),
  ...(config.from === undefined ? {} : { from: config.from }),
});

// A connect send error's `message` is safe to log by its contract (never the
// credential nor the message body), so it is carried into the AuthError.
const deliveryFailed =
  (channel: "email" | "sms") =>
  (cause: Connect.EmailSendError | Connect.SmsSendError): Errors.AuthError =>
    new Errors.AuthError({
      message: `${channel === "email" ? "Email" : "SMS"} delivery via ${cause.provider} failed: ${cause.message}`,
      cause,
    });

const connectEmailSender = (
  email: typeof Connect.EmailService.Service,
  config: ConnectEmailSenderConfig,
): typeof EmailSender.Service => ({
  send: (message) =>
    Effect.suspend(() => email.send(toConnectEmail(message, config))).pipe(
      Effect.asVoid,
      Effect.mapError(deliveryFailed("email")),
      Effect.withSpan("effect-auth.delivery.send", {
        attributes: { channel: "email", purpose: message.purpose },
      }),
    ),
});

const connectSmsSender = (
  sms: typeof Connect.SmsService.Service,
  config: ConnectSmsSenderConfig,
): typeof SmsSender.Service => ({
  send: (message) =>
    Effect.suspend(() => sms.send(toConnectSms(message, config))).pipe(
      Effect.asVoid,
      Effect.mapError(deliveryFailed("sms")),
      Effect.withSpan("effect-auth.delivery.send", {
        attributes: { channel: "sms", purpose: message.purpose },
      }),
    ),
});

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
>()("@effect-auth/EmailSender") {
  /**
   * A transport that sends nothing and logs each message's recipient and
   * purpose at warning level (never its `params`, which hold the token or
   * code). For development only, opted into explicitly: every flow that waits
   * on a message (a magic link, a code, a reset link) is a lockout behind it.
   */
  static readonly logging: Layer.Layer<EmailSender> = Layer.succeed(EmailSender, {
    send: (message) => logUnsent("email", message),
  });

  /**
   * An `EmailSender` over an effect-connect `EmailService`: each message is
   * rendered with `config.render` and sent from `config.from`. A failed send
   * is an `AuthError` whose `cause` is the provider's `EmailSendError`.
   */
  static readonly fromConnect: (
    email: typeof Connect.EmailService.Service,
    config: ConnectEmailSenderConfig,
  ) => typeof EmailSender.Service = connectEmailSender;

  /**
   * {@link EmailSender.fromConnect} as a layer over the `EmailService` in
   * context: provide any effect-connect email provider beneath it.
   *
   * @example
   * ```ts
   * import assert from "node:assert/strict"
   * import { Effect, Layer } from "effect"
   * import { EmailService, type EmailMessage } from "@thomasfosterau/effect-connect"
   * import { EmailSender } from "@thomasfosterau/effect-auth"
   *
   * const sent: Array<EmailMessage> = []
   * const Email = EmailSender.layerConnect({ from: { email: "noreply@example.com" } }).pipe(
   *   Layer.provide(EmailService.layerRecording(sent)),
   * )
   *
   * await Effect.runPromise(
   *   EmailSender.use((sender) =>
   *     sender.send({ to: "ada@example.com", purpose: "magic-link", params: { token: "t" } }),
   *   ).pipe(Effect.provide(Email)),
   * )
   * assert.equal(sent[0]?.subject, "Your sign-in link")
   * ```
   */
  static readonly layerConnect = (
    config: ConnectEmailSenderConfig,
  ): Layer.Layer<EmailSender, never, Connect.EmailService> =>
    Layer.effect(
      EmailSender,
      Connect.EmailService.use((email) => Effect.succeed(connectEmailSender(email, config))),
    );
}

/** The single contract an SMS-delivery adapter implements. */
export class SmsSender extends Context.Service<
  SmsSender,
  {
    readonly send: (message: SmsMessage) => Effect.Effect<void, Errors.AuthError>;
  }
>()("@effect-auth/SmsSender") {
  /** The SMS counterpart of {@link EmailSender.logging}: logs, sends nothing. */
  static readonly logging: Layer.Layer<SmsSender> = Layer.succeed(SmsSender, {
    send: (message) => logUnsent("sms", message),
  });

  /**
   * An `SmsSender` over an effect-connect `SmsService`: each message is
   * rendered with `config.render` and sent from `config.from`. A failed send
   * is an `AuthError` whose `cause` is the provider's `SmsSendError`.
   */
  static readonly fromConnect: (
    sms: typeof Connect.SmsService.Service,
    config?: ConnectSmsSenderConfig,
  ) => typeof SmsSender.Service = (sms, config = {}) => connectSmsSender(sms, config);

  /** {@link SmsSender.fromConnect} as a layer over the `SmsService` in context. */
  static readonly layerConnect = (
    config: ConnectSmsSenderConfig = {},
  ): Layer.Layer<SmsSender, never, Connect.SmsService> =>
    Layer.effect(
      SmsSender,
      Connect.SmsService.use((sms) => Effect.succeed(connectSmsSender(sms, config))),
    );
}

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
    sender.send({ to, purpose: "email-verification", params: { token } }),

  /**
   * `AuthLifecycleConfig.sendExistingAccountNotice`: tells an address's holder
   * that someone tried to sign up with it. It carries no token, so `params`
   * is empty.
   */
  sendExistingAccountNotice: (to: string) =>
    sender.send({ to, purpose: "existing-account", params: {} }),

  /** `MagicLinkConfig.sendMagicLink` */
  sendMagicLink: (email: string, token: string) =>
    sender.send({ to: email, purpose: "magic-link", params: { token } }),

  /** `EmailOtpConfig.sendVerificationOtp` */
  sendVerificationOtp: (email: string, otp: string, purpose: EmailOtpPurpose) =>
    sender.send({ to: email, purpose: `email-otp:${purpose}`, params: { otp } }),

  /** `PasswordResetConfig.sendResetPassword` */
  sendResetPassword: (email: string, token: string) =>
    sender.send({ to: email, purpose: "password-reset", params: { token } }),

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

  /**
   * `AccountManagementConfig.sendEmailChangeNotice` (sent to the OLD address),
   * with `params.newEmail`.
   */
  sendEmailChangeNotice: (params: {
    readonly user: Types.User;
    readonly oldEmail: string;
    readonly newEmail: string;
  }) =>
    sender.send({
      to: params.oldEmail,
      purpose: "email-change-requested",
      params: { newEmail: params.newEmail },
    }),

  /** `AccountManagementConfig.sendDeleteAccountVerification` */
  sendDeleteAccountVerification: (params: {
    readonly user: Types.User;
    readonly email: Option.Option<string>;
    readonly token: string;
  }) =>
    Option.match(params.email, {
      onNone: () =>
        Effect.fail(
          new Errors.AuthError({ message: "User has no email for account-deletion delivery" }),
        ),
      onSome: (to) =>
        sender.send({
          to,
          purpose: "delete-account",
          params: { token: params.token },
        }),
    }),

  /** `OtpSecondFactorConfig.sendOtp`, delivering the code to the user's email identifier. */
  sendSecondFactorOtp: (user: Types.User, otp: string) =>
    Effect.gen(function* () {
      const email = anyEmailValue(yield* identifiers.listByUser(user.id));
      if (Option.isNone(email)) {
        return yield* new Errors.AuthError({ message: "User has no email for second-factor OTP" });
      }
      yield* sender.send({ to: email.value, purpose: "second-factor-otp", params: { otp } });
      return undefined;
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
    sender.send({ to: phoneNumber, purpose: `phone-otp:${purpose}`, params: { otp } }),

  /**
   * `OtpSecondFactorConfig.sendOtp`, delivering the code to the user's
   * `phone` identifier. Fails with `AuthError` when the user has no phone
   * number on file.
   */
  sendSecondFactorOtp: (user: Types.User, otp: string) =>
    Effect.gen(function* () {
      const phoneNumber = yield* getPhoneNumber(identifiers, user.id);
      if (Option.isNone(phoneNumber)) {
        return yield* new Errors.AuthError({
          message: "User has no phone number for second-factor OTP",
        });
      }
      yield* sender.send({ to: phoneNumber.value, purpose: "second-factor-otp", params: { otp } });
      return undefined;
    }),
});
