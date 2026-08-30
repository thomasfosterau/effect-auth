/**
 * {@link SMSSender} adapter for [Twilio](https://www.twilio.com), talking to
 * Twilio's Messages API (`POST /Accounts/:sid/Messages.json`) with plain
 * `fetch` — no SDK dependency.
 *
 * The default renderer produces a minimal, purpose-keyed SMS body (see
 * {@link defaultRender}). It exists so the adapter is usable out of the box
 * and in tests; **real applications should supply their own `render`** for
 * branded, localized copy.
 *
 * @module twilio/twilio
 */
import { Effect, Layer, Redacted } from "effect";
import { AuthError, SMSSender, type SMSMessage } from "@thomasfosterau/effect-auth";

// ---------------------------------------------------------------------------
// Default renderer
// ---------------------------------------------------------------------------

const purposeLead = (purpose: SMSMessage["purpose"]): string => {
  switch (purpose) {
    case "second-factor-otp":
      return "Your verification code";
    default:
      if (purpose.startsWith("phone-otp:")) return "Your verification code";
      return "Message";
  }
};

/**
 * The built-in renderer: a purpose-keyed lead-in (e.g. "Your verification
 * code" for OTP purposes) followed by the OTP or token from the message's
 * `params`. It has no branding and no localization; it's a functional
 * fallback, not a template system. Real applications should pass their own
 * `render` in {@link TwilioSMSSenderConfig}.
 */
export const defaultRender = (message: SMSMessage): string => {
  const lead = purposeLead(message.purpose);
  const { otp, token } = message.params;
  const value = otp ?? token;
  return value !== undefined ? `${lead}: ${value}` : lead;
};

// ---------------------------------------------------------------------------
// Config
// ---------------------------------------------------------------------------

/** Configuration for {@link twilioSMSSender}. */
export interface TwilioSMSSenderConfig {
  /** Twilio Account SID (starts with `AC`). */
  readonly accountSid: string;
  /** Twilio Auth Token. Wrap with `Redacted.make(...)` or read via `Config.redacted(...)`. */
  readonly authToken: Redacted.Redacted<string>;
  /** The sending phone number (E.164) or Messaging Service SID. */
  readonly from: string;
  /**
   * Render a message into the SMS body. Defaults to {@link defaultRender};
   * supply your own for branded/localized copy.
   */
  readonly render?: (message: SMSMessage) => string;
  /** Override the API base URL — for testing against a local stub. Defaults to `https://api.twilio.com`. */
  readonly baseUrl?: string;
  /** Inject a `fetch` implementation — for testing. Defaults to `globalThis.fetch`. */
  readonly fetch?: typeof fetch;
}

const DEFAULT_BASE_URL = "https://api.twilio.com";

interface TwilioErrorBody {
  readonly code?: number;
  readonly message?: string;
}

const isTwilioErrorBody = (value: unknown): value is TwilioErrorBody =>
  typeof value === "object" && value !== null;

/** Parse Twilio's `{ code, message }` error body, when present, into readable text. */
const describeTwilioError = (status: number, bodyText: string): string => {
  try {
    const parsed: unknown = JSON.parse(bodyText);
    if (isTwilioErrorBody(parsed) && (parsed.code !== undefined || parsed.message !== undefined)) {
      const code = parsed.code !== undefined ? `code ${parsed.code}` : `status ${status}`;
      const message = parsed.message ?? "no message";
      return `${code}: ${message}`;
    }
  } catch {
    // Not JSON — fall through to the raw body.
  }
  return `status ${status}: ${bodyText}`;
};

// ---------------------------------------------------------------------------
// Sender
// ---------------------------------------------------------------------------

/**
 * Build an {@link SMSSender} service backed by Twilio's Messages API. Every
 * failure (network, non-2xx response) surfaces as an {@link AuthError} whose
 * `cause` carries the response `status`/`body` and, when parseable, Twilio's
 * own error `code`/`message` — the auth token is never included.
 *
 * @example
 * ```ts
 * import { Redacted } from "effect";
 * import { twilioSMSSender } from "@thomasfosterau/effect-auth-twilio";
 *
 * const sender = twilioSMSSender({
 *   accountSid: process.env.TWILIO_ACCOUNT_SID!,
 *   authToken: Redacted.make(process.env.TWILIO_AUTH_TOKEN!),
 *   from: "+15551234567",
 * });
 * ```
 */
export const twilioSMSSender = (config: TwilioSMSSenderConfig): typeof SMSSender.Service => {
  const baseUrl = config.baseUrl ?? DEFAULT_BASE_URL;
  const doFetch = config.fetch ?? fetch;
  const render = config.render ?? defaultRender;

  const send = (message: SMSMessage) =>
    Effect.gen(function* () {
      const body = render(message);
      const form = new URLSearchParams({ Body: body, From: config.from, To: message.to });
      const credentials = `${config.accountSid}:${Redacted.value(config.authToken)}`;

      const response = yield* Effect.tryPromise({
        try: () =>
          doFetch(`${baseUrl}/2010-04-01/Accounts/${config.accountSid}/Messages.json`, {
            method: "POST",
            headers: {
              Authorization: `Basic ${Buffer.from(credentials).toString("base64")}`,
              "Content-Type": "application/x-www-form-urlencoded",
            },
            body: form.toString(),
          }),
        catch: (cause) => new AuthError({ message: "Failed to reach Twilio API", cause }),
      });

      if (!response.ok) {
        const bodyText = yield* Effect.promise(() => response.text());
        return yield* new AuthError({
          message: `Twilio API request failed (${describeTwilioError(response.status, bodyText)})`,
          cause: { status: response.status, body: bodyText },
        });
      }
    }).pipe(
      Effect.withSpan("effect-auth-twilio.send", {
        attributes: { purpose: message.purpose },
      }),
    );

  return { send };
};

/**
 * A `Layer` providing {@link SMSSender} backed by {@link twilioSMSSender}.
 *
 * @example
 * ```ts
 * import { Redacted } from "effect";
 * import { layer as twilioLayer } from "@thomasfosterau/effect-auth-twilio";
 *
 * const SMSLayer = twilioLayer({
 *   accountSid: process.env.TWILIO_ACCOUNT_SID!,
 *   authToken: Redacted.make(process.env.TWILIO_AUTH_TOKEN!),
 *   from: "+15551234567",
 * });
 * ```
 */
export const layer = (config: TwilioSMSSenderConfig): Layer.Layer<SMSSender> =>
  Layer.succeed(SMSSender, twilioSMSSender(config));
