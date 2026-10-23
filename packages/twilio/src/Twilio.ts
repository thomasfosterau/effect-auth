/**
 * {@link SmsSender} adapter for [Twilio](https://www.twilio.com), talking to
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
import { Data, Effect, Layer, Match, Option, Redacted, Schema } from "effect";
import { AuthError, SmsSender, type SmsMessage } from "@thomasfosterau/effect-auth";

// ---------------------------------------------------------------------------
// Default renderer
// ---------------------------------------------------------------------------

const purposeLead = (purpose: SmsMessage["purpose"]): string =>
  Match.value(purpose).pipe(
    Match.when("second-factor-otp", () => "Your verification code"),
    Match.orElse((other) =>
      other.startsWith("phone-otp:") ? "Your verification code" : "Message",
    ),
  );

/**
 * The built-in renderer: a purpose-keyed lead-in (e.g. "Your verification
 * code" for OTP purposes) followed by the OTP or token from the message's
 * `params`. It has no branding and no localization; it's a functional
 * fallback, not a template system. Real applications should pass their own
 * `render` in {@link TwilioSmsSenderConfig}.
 */
export const defaultRender = (message: SmsMessage): string => {
  const lead = purposeLead(message.purpose);
  const { otp, token } = message.params;
  const value = otp ?? token;
  return value !== undefined ? `${lead}: ${value}` : lead;
};

// ---------------------------------------------------------------------------
// Config
// ---------------------------------------------------------------------------

/** Configuration for {@link twilioSmsSender}. */
export interface TwilioSmsSenderConfig {
  /** Twilio Account SID (starts with `AC`). */
  readonly accountSid: string;
  /** Twilio Auth Token. Wrap with `Redacted.make(...)` or read via `Config.Redacted(...)`. */
  readonly authToken: Redacted.Redacted<string>;
  /** The sending phone number (E.164) or Messaging Service SID. */
  readonly from: string;
  /**
   * Render a message into the SMS body. Defaults to {@link defaultRender};
   * supply your own for branded/localized copy.
   */
  readonly render?: ((message: SmsMessage) => string) | undefined;
  /** Override the API base URL — for testing against a local stub. Defaults to `https://api.twilio.com`. */
  readonly baseUrl?: string | undefined;
  /** Inject a `fetch` implementation — for testing. Defaults to `globalThis.fetch`. */
  readonly fetch?: typeof fetch | undefined;
}

const DEFAULT_BASE_URL = "https://api.twilio.com";

/** Reading a non-2xx response's body failed; raised as a defect. */
class ResponseBodyError extends Data.TaggedError("ResponseBodyError")<{
  readonly cause: unknown;
}> {}

/**
 * Twilio's `{ code, message }` error body. The fields are left untyped so any
 * JSON object is accepted and its `code`/`message` are rendered as they are.
 */
const TwilioErrorBodyJson = Schema.fromJsonString(
  Schema.Struct({
    code: Schema.optionalKey(Schema.Unknown),
    message: Schema.optionalKey(Schema.Unknown),
  }),
);

const decodeTwilioErrorBody = Schema.decodeUnknownOption(TwilioErrorBodyJson);

/** Parse Twilio's `{ code, message }` error body, when present, into readable text. */
const describeTwilioError = (status: number, bodyText: string): string =>
  Option.match(
    // Not JSON (or not an object) — fall through to the raw body.
    Option.filter(
      decodeTwilioErrorBody(bodyText),
      (parsed) => parsed.code !== undefined || parsed.message !== undefined,
    ),
    {
      onNone: () => `status ${status}: ${bodyText}`,
      onSome: (parsed) => {
        const code = parsed.code !== undefined ? `code ${String(parsed.code)}` : `status ${status}`;
        const message = parsed.message ?? "no message";
        return `${code}: ${String(message)}`;
      },
    },
  );

// ---------------------------------------------------------------------------
// Sender
// ---------------------------------------------------------------------------

/**
 * Build an {@link SmsSender} service backed by Twilio's Messages API. Every
 * failure (network, non-2xx response) surfaces as an {@link AuthError} whose
 * `cause` carries the response `status`/`body` and, when parseable, Twilio's
 * own error `code`/`message` — the auth token is never included.
 *
 * @example
 * ```ts
 * import { Redacted } from "effect";
 * import { twilioSmsSender } from "@thomasfosterau/effect-auth-twilio";
 *
 * const sender = twilioSmsSender({
 *   accountSid: process.env.TWILIO_ACCOUNT_SID!,
 *   authToken: Redacted.make(process.env.TWILIO_AUTH_TOKEN!),
 *   from: "+15551234567",
 * });
 * ```
 */
export const twilioSmsSender = (config: TwilioSmsSenderConfig): typeof SmsSender.Service => {
  const baseUrl = config.baseUrl ?? DEFAULT_BASE_URL;
  const doFetch = config.fetch ?? fetch;
  const render = config.render ?? defaultRender;

  const send = (message: SmsMessage) =>
    Effect.gen(function* () {
      const body = render(message);
      const form = new URLSearchParams({ Body: body, From: config.from, To: message.to });
      const credentials = `${config.accountSid}:${Redacted.value(config.authToken)}`;

      const response = yield* Effect.tryPromise({
        try: () =>
          doFetch(`${baseUrl}/2010-04-01/Accounts/${config.accountSid}/Messages.json`, {
            method: "POST",
            headers: {
              Authorization: `Basic ${btoa(credentials)}`,
              "Content-Type": "application/x-www-form-urlencoded",
            },
            body: form.toString(),
          }),
        catch: (cause) => new AuthError({ message: "Failed to reach Twilio API", cause }),
      });

      if (!response.ok) {
        const bodyText = yield* Effect.tryPromise({
          try: () => response.text(),
          catch: (cause) => new ResponseBodyError({ cause }),
        }).pipe(Effect.orDie);
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
 * A `Layer` providing {@link SmsSender} backed by {@link twilioSmsSender}.
 *
 * @example
 * ```ts
 * import { Redacted } from "effect";
 * import { layer as twilioLayer } from "@thomasfosterau/effect-auth-twilio";
 *
 * const SmsLayer = twilioLayer({
 *   accountSid: process.env.TWILIO_ACCOUNT_SID!,
 *   authToken: Redacted.make(process.env.TWILIO_AUTH_TOKEN!),
 *   from: "+15551234567",
 * });
 * ```
 */
export const layer = (config: TwilioSmsSenderConfig): Layer.Layer<SmsSender> =>
  Layer.succeed(SmsSender, twilioSmsSender(config));
