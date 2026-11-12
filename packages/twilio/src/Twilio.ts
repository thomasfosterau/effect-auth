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
import { Effect, Formatter, Layer, Match, Redacted } from "effect";
import * as Option from "effect/Option";
import * as P from "effect/Predicate";
import * as Schema from "effect/Schema";
import * as Stream from "effect/Stream";
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
  readonly authToken: Redacted.Redacted;
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

/**
 * The most characters of a non-2xx response body an {@link AuthError} keeps
 * (#606), in its `cause` and in its message. A longer body is cut here and
 * ends in {@link TRUNCATION_MARKER}.
 */
export const MAX_ERROR_BODY_CHARS = 1024;

/** Ends an error-body excerpt that was cut at {@link MAX_ERROR_BODY_CHARS}. */
export const TRUNCATION_MARKER = "…[truncated]";

/** Stands in for a credential an upstream body echoed back. */
const REDACTED_MARKER = "[redacted]";

/** Drop every occurrence of each secret from `text`. */
const scrubSecrets = (text: string, secrets: ReadonlyArray<string>): string =>
  secrets.reduce(
    (scrubbed, secret) => (secret === "" ? scrubbed : scrubbed.replaceAll(secret, REDACTED_MARKER)),
    text,
  );

/**
 * The excerpt of a body read up to `MAX_ERROR_BODY_CHARS + longest`
 * characters, secrets scrubbed. A read that stopped early also loses its last
 * `longest` characters, where a secret cut off mid-way would sit.
 */
const boundedExcerpt = (raw: string, secrets: ReadonlyArray<string>, longest: number): string => {
  const scrubbed = scrubSecrets(raw, secrets);
  if (raw.length <= MAX_ERROR_BODY_CHARS + longest && scrubbed.length <= MAX_ERROR_BODY_CHARS) {
    return scrubbed;
  }
  const cut = raw.length > MAX_ERROR_BODY_CHARS + longest ? scrubbed.length - longest : Infinity;
  return `${scrubbed.slice(0, Math.min(MAX_ERROR_BODY_CHARS, cut))}${TRUNCATION_MARKER}`;
};

/** Stops the body read once more than `limit` characters are in. */
const readPast =
  (limit: number) =>
  (text: string): boolean =>
    text.length > limit;

/**
 * A non-2xx response's body as a bounded, scrubbed excerpt. The stream is
 * read only until it passes the limit, then cancelled.
 */
const errorBodyExcerpt = (
  response: Response,
  secrets: ReadonlyArray<string>,
): Effect.Effect<string, AuthError> => {
  const stream = response.body;
  if (stream === null) return Effect.succeed("");
  const longest = Math.max(0, ...secrets.map((secret) => secret.length));
  return Stream.runLast(
    Stream.fromReadableStream({
      evaluate: () => stream,
      onError: (cause) =>
        new AuthError({
          message: `Failed to read the Twilio API's error response (status ${response.status})`,
          cause,
        }),
    }).pipe(
      Stream.decodeText,
      Stream.scan(
        () => "",
        (read, chunk) => read + chunk,
      ),
      Stream.takeUntil(readPast(MAX_ERROR_BODY_CHARS + longest)),
    ),
  ).pipe(
    Effect.map((read) =>
      boundedExcerpt(
        Option.getOrElse(read, () => ""),
        secrets,
        longest,
      ),
    ),
  );
};

/**
 * Whether a `redirect: "manual"` response is a redirect. workerd and Node
 * return the real 3xx (`type: "default"`); a browser returns an
 * `"opaqueredirect"` with status 0. The status decides; the opaque type only
 * adds to it.
 */
const isRedirect = (response: Response): boolean =>
  (response.status >= 300 && response.status <= 399) ||
  response.status === 0 ||
  response.type === "opaqueredirect";

/** Cancel a redirect's body unread; one that fails to cancel is dropped all the same. */
const cancelBody = (response: Response): Effect.Effect<void> => {
  const stream = response.body;
  if (stream === null) return Effect.void;
  return Effect.tryPromise({
    try: () => stream.cancel(),
    catch: (cause) => new AuthError({ message: "Failed to cancel a redirect's body", cause }),
  }).pipe(Effect.ignore);
};

/**
 * A redirect as an {@link AuthError} with only its status: the body is
 * cancelled unread and `Location` is never read, so nothing it names reaches
 * the error or a second request.
 */
const redirectFailure = (response: Response): Effect.Effect<never, AuthError> =>
  cancelBody(response).pipe(
    Effect.andThen(
      Effect.fail(
        new AuthError({
          message: `Twilio API responded with a redirect (status ${response.status}), which is not followed`,
          cause: { status: response.status },
        }),
      ),
    ),
  );

/**
 * Twilio's `{ code, message }` error body. The fields are any JSON value, so
 * any JSON object is accepted and its `code`/`message` are rendered as they are.
 */
const TwilioErrorBodyJson = Schema.fromJsonString(
  Schema.Struct({
    code: Schema.optionalKey(Schema.Json),
    message: Schema.optionalKey(Schema.Json),
  }),
);

const decodeTwilioErrorBody = Schema.decodeUnknownOption(TwilioErrorBodyJson);

/** A field of the error body as text: a string as is, anything else formatted. */
const renderField = (value: Schema.Json): string =>
  P.isString(value) ? value : Formatter.format(value);

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
        const code =
          parsed.code !== undefined ? `code ${renderField(parsed.code)}` : `status ${status}`;
        return `${code}: ${renderField(parsed.message ?? "no message")}`;
      },
    },
  );

// ---------------------------------------------------------------------------
// Sender
// ---------------------------------------------------------------------------

/**
 * Build an {@link SmsSender} service backed by Twilio's Messages API. Every
 * failure (network, redirect, non-2xx response) surfaces as an
 * {@link AuthError}; a non-2xx one's `cause` carries the response `status` and
 * a `body` excerpt of at most {@link MAX_ERROR_BODY_CHARS} characters, and its
 * message Twilio's own error `code`/`message` when the body parses. The auth
 * token is never included, even when the response echoes it. Redirects are
 * never followed: the request is sent with `redirect: "manual"` (workerd
 * rejects `"error"`), and any 3xx, status 0 or opaque redirect fails with
 * only its status, so the credentials go to `baseUrl` only.
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
      const authToken = Redacted.value(config.authToken);
      const basic = btoa(`${config.accountSid}:${authToken}`);

      const response = yield* Effect.tryPromise({
        try: (signal) =>
          doFetch(`${baseUrl}/2010-04-01/Accounts/${config.accountSid}/Messages.json`, {
            method: "POST",
            redirect: "manual",
            signal,
            headers: {
              Authorization: `Basic ${basic}`,
              "Content-Type": "application/x-www-form-urlencoded",
            },
            body: form.toString(),
          }),
        catch: (cause) => new AuthError({ message: "Failed to reach Twilio API", cause }),
      });

      if (isRedirect(response)) return yield* redirectFailure(response);
      if (!response.ok) {
        const bodyText = yield* errorBodyExcerpt(response, [authToken, basic]);
        return yield* new AuthError({
          message: `Twilio API request failed (${describeTwilioError(response.status, bodyText)})`,
          cause: { status: response.status, body: bodyText },
        });
      }
      return yield* Effect.void;
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
