/**
 * {@link EmailSender} adapter for [Resend](https://resend.com), talking to
 * Resend's REST API (`POST /emails`) with plain `fetch` — no SDK dependency.
 *
 * The default renderer produces minimal, purpose-keyed subject/text content
 * (see {@link defaultRender}). It exists so the adapter is usable out of the
 * box and in tests; **real applications should supply their own `render`**
 * for branded, localized templates.
 *
 * @module resend/resend
 */
import { Effect, Layer, Redacted } from "effect";
import { AuthError, EmailSender, type EmailMessage } from "@thomasfosterau/effect-auth";

// ---------------------------------------------------------------------------
// Default renderer
// ---------------------------------------------------------------------------

/** The rendered content Resend's `/emails` endpoint expects, minus routing fields. */
export interface RenderedEmail {
  readonly subject: string;
  readonly html?: string;
  readonly text?: string;
}

const purposeSubject = (purpose: EmailMessage["purpose"]): string => {
  switch (purpose) {
    case "email-verification":
      return "Verify your email address";
    case "magic-link":
      return "Your sign-in link";
    case "password-reset":
      return "Reset your password";
    case "change-email":
      return "Confirm your new email address";
    case "delete-account":
      return "Confirm account deletion";
    case "second-factor-otp":
      return "Your verification code";
    case "existing-account":
      return "Someone tried to sign up with your email address";
    default:
      return purpose.startsWith("email-otp:") ? "Your verification code" : "Action required";
  }
};

// The `"existing-account"` notice carries no params: it only tells the
// address's holder that a sign-up was attempted with it.
const EXISTING_ACCOUNT_TEXT = [
  "Someone tried to create an account with this email address, but it already belongs to an account. Nothing about your account was changed.",
  "If this was you, sign in instead, or reset your password if you have forgotten it.",
  "If it wasn't you, you can ignore this email.",
].join("\n\n");

/**
 * The built-in renderer: a purpose-keyed subject line (e.g. "Your
 * verification code" for OTP purposes) and a plain-text body carrying
 * whatever the message's `params` hold — the OTP code when `params.otp` is
 * set, and a link when `params.url` (or, failing that, `params.token`) is
 * set. The `"existing-account"` notice gets a fixed body saying someone tried
 * to sign up with the address and pointing at sign-in or password reset. It has no HTML, no branding and no localization; it's a functional
 * fallback, not a template system. Real applications should pass their own
 * `render` in {@link ResendEmailSenderConfig}.
 */
export const defaultRender = (message: EmailMessage): RenderedEmail => {
  const subject = purposeSubject(message.purpose);
  if (message.purpose === "existing-account") {
    return { subject, text: EXISTING_ACCOUNT_TEXT };
  }
  const { otp, token, url } = message.params;

  const lines: string[] = [];
  if (otp !== undefined) lines.push(`Your code: ${otp}`);
  if (url !== undefined) lines.push(`Continue here: ${url}`);
  else if (token !== undefined) lines.push(`Your token: ${token}`);

  return { subject, text: lines.length > 0 ? lines.join("\n\n") : "Please continue in the app." };
};

// ---------------------------------------------------------------------------
// Config
// ---------------------------------------------------------------------------

/** Configuration for {@link resendEmailSender}. */
export interface ResendEmailSenderConfig {
  /** Resend API key. Wrap with `Redacted.make(...)` or read via `Config.Redacted(...)`. */
  readonly apiKey: Redacted.Redacted<string>;
  /** The `from` address (and optional display name, e.g. `"App <noreply@example.com>"`). */
  readonly from: string;
  /**
   * Render a message into Resend's email fields. Defaults to
   * {@link defaultRender}; supply your own for branded/localized templates.
   */
  readonly render?: (message: EmailMessage) => RenderedEmail;
  /** Override the API base URL — for testing against a local stub. Defaults to `https://api.resend.com`. */
  readonly baseUrl?: string;
  /** Inject a `fetch` implementation — for testing. Defaults to `globalThis.fetch`. */
  readonly fetch?: typeof fetch;
}

const DEFAULT_BASE_URL = "https://api.resend.com";

// ---------------------------------------------------------------------------
// Sender
// ---------------------------------------------------------------------------

/**
 * Build an {@link EmailSender} service backed by Resend's REST API. Every
 * failure (network, non-2xx response) surfaces as an {@link AuthError} whose
 * `cause` carries the response `status`/`body` — the API key is never
 * included.
 *
 * @example
 * ```ts
 * import { Redacted } from "effect";
 * import { resendEmailSender } from "@thomasfosterau/effect-auth-resend";
 *
 * const sender = resendEmailSender({
 *   apiKey: Redacted.make(process.env.RESEND_API_KEY!),
 *   from: "App <noreply@example.com>",
 * });
 * ```
 */
export const resendEmailSender = (config: ResendEmailSenderConfig): typeof EmailSender.Service => {
  const baseUrl = config.baseUrl ?? DEFAULT_BASE_URL;
  const doFetch = config.fetch ?? fetch;
  const render = config.render ?? defaultRender;

  const send = (message: EmailMessage) =>
    Effect.gen(function* () {
      const rendered = render(message);

      const payload: Record<string, unknown> = {
        from: config.from,
        to: message.to,
        subject: rendered.subject,
        ...(rendered.html !== undefined && { html: rendered.html }),
        ...(rendered.text !== undefined && { text: rendered.text }),
      };

      const response = yield* Effect.tryPromise({
        try: () =>
          doFetch(`${baseUrl}/emails`, {
            method: "POST",
            headers: {
              Authorization: `Bearer ${Redacted.value(config.apiKey)}`,
              "Content-Type": "application/json",
            },
            body: JSON.stringify(payload),
          }),
        catch: (cause) => new AuthError({ message: "Failed to reach Resend API", cause }),
      });

      if (!response.ok) {
        const body = yield* Effect.promise(() => response.text());
        return yield* new AuthError({
          message: `Resend API request failed with status ${response.status}`,
          cause: { status: response.status, body },
        });
      }
    }).pipe(
      Effect.withSpan("effect-auth-resend.send", {
        attributes: { purpose: message.purpose },
      }),
    );

  return { send };
};

/**
 * A `Layer` providing {@link EmailSender} backed by {@link resendEmailSender}.
 *
 * @example
 * ```ts
 * import { Redacted, Layer } from "effect";
 * import { layer as resendLayer } from "@thomasfosterau/effect-auth-resend";
 *
 * const EmailLayer = resendLayer({
 *   apiKey: Redacted.make(process.env.RESEND_API_KEY!),
 *   from: "App <noreply@example.com>",
 * });
 * ```
 */
export const layer = (config: ResendEmailSenderConfig): Layer.Layer<EmailSender> =>
  Layer.succeed(EmailSender, resendEmailSender(config));
