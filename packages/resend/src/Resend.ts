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
import { Config, Effect, Layer, Match, Redacted } from "effect";
import * as Arr from "effect/Array";
import * as Option from "effect/Option";
import * as Schema from "effect/Schema";
import * as Stream from "effect/Stream";
import { AuthError, EmailSender, type EmailMessage } from "@thomasfosterau/effect-auth";

// ---------------------------------------------------------------------------
// Default renderer
// ---------------------------------------------------------------------------

/** The rendered content Resend's `/emails` endpoint expects, minus routing fields. */
export interface RenderedEmail {
  readonly subject: string;
  readonly html?: string | undefined;
  readonly text?: string | undefined;
}

const purposeSubject = (purpose: EmailMessage["purpose"]): string =>
  Match.value(purpose).pipe(
    Match.when("email-verification", () => "Verify your email address"),
    Match.when("magic-link", () => "Your sign-in link"),
    Match.when("password-reset", () => "Reset your password"),
    Match.when("change-email", () => "Confirm your new email address"),
    Match.when("delete-account", () => "Confirm account deletion"),
    Match.when("second-factor-otp", () => "Your verification code"),
    Match.when("existing-account", () => "Someone tried to sign up with your email address"),
    Match.orElse((other) =>
      other.startsWith("email-otp:") ? "Your verification code" : "Action required",
    ),
  );

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

  return {
    subject,
    text: Arr.isReadonlyArrayNonEmpty(lines) ? lines.join("\n\n") : "Please continue in the app.",
  };
};

// ---------------------------------------------------------------------------
// Config
// ---------------------------------------------------------------------------

/** Configuration for {@link resendEmailSender}. */
export interface ResendEmailSenderConfig {
  /** Resend API key. Wrap with `Redacted.make(...)` or read via `Config.Redacted(...)`. */
  readonly apiKey: Redacted.Redacted;
  /** The `from` address (and optional display name, e.g. `"App <noreply@example.com>"`). */
  readonly from: string;
  /**
   * Render a message into Resend's email fields. Defaults to
   * {@link defaultRender}; supply your own for branded/localized templates.
   */
  readonly render?: ((message: EmailMessage) => RenderedEmail) | undefined;
  /** Override the API base URL — for testing against a local stub. Defaults to `https://api.resend.com`. */
  readonly baseUrl?: string | undefined;
  /** Inject a `fetch` implementation — for testing. Defaults to `globalThis.fetch`. */
  readonly fetch?: typeof fetch | undefined;
}

const DEFAULT_BASE_URL = "https://api.resend.com";

/** The JSON body of Resend's `POST /emails`. */
const ResendPayloadJson = Schema.fromJsonString(
  Schema.Struct({
    from: Schema.String,
    to: Schema.String,
    subject: Schema.String,
    html: Schema.optionalKey(Schema.String),
    text: Schema.optionalKey(Schema.String),
  }),
);

const encodePayload = Schema.encodeSync(ResendPayloadJson);

// ---------------------------------------------------------------------------
// Error bodies
// ---------------------------------------------------------------------------

/**
 * The most characters of a non-2xx response body an {@link AuthError}'s
 * `cause` keeps (#606). A longer body is cut here and ends in
 * {@link TRUNCATION_MARKER}.
 */
export const MAX_ERROR_BODY_CHARS = 1024;

/** Ends an error-body excerpt that was cut at {@link MAX_ERROR_BODY_CHARS}. */
export const TRUNCATION_MARKER = "…[truncated]";

/** Stands in for a credential an upstream body echoed back. */
const REDACTED_MARKER = "[redacted]";

/**
 * The excerpt of a body read up to `MAX_ERROR_BODY_CHARS + longest`
 * characters, with every occurrence of a secret replaced. When the read
 * stopped early, the last `longest` characters are dropped as well, so a
 * secret cut off at the end of the read leaves no prefix behind.
 */
const excerptBody = (raw: string, secrets: ReadonlyArray<string>, longest: number): string => {
  const complete = raw.length <= MAX_ERROR_BODY_CHARS + longest;
  const scrubbed = secrets.reduce(
    (text, secret) => (secret === "" ? text : text.replaceAll(secret, REDACTED_MARKER)),
    raw,
  );
  const keep = complete ? scrubbed.length : scrubbed.length - longest;
  return complete && keep <= MAX_ERROR_BODY_CHARS
    ? scrubbed
    : `${scrubbed.slice(0, Math.min(MAX_ERROR_BODY_CHARS, keep))}${TRUNCATION_MARKER}`;
};

/** Whether the body read so far has passed `limit` characters, so reading stops. */
const pastLimit =
  (limit: number) =>
  (text: string): boolean =>
    text.length > limit;

/**
 * Read a non-2xx response's body as a bounded excerpt: the stream is read
 * only until it passes the limit and is then cancelled, and no `secrets`
 * survive into the result.
 */
const readErrorBody = (
  response: Response,
  secrets: ReadonlyArray<string>,
): Effect.Effect<string, AuthError> => {
  const body = response.body;
  if (body === null) return Effect.succeed("");
  const longest = Math.max(0, ...secrets.map((secret) => secret.length));
  return Stream.fromReadableStream({
    evaluate: () => body,
    onError: (cause) =>
      new AuthError({
        message: `Failed to read the Resend API's error response (status ${response.status})`,
        cause,
      }),
  }).pipe(
    Stream.decodeText,
    Stream.scan(
      () => "",
      (text, chunk) => text + chunk,
    ),
    Stream.takeUntil(pastLimit(MAX_ERROR_BODY_CHARS + longest)),
    Stream.runLast,
    Effect.map((text) =>
      excerptBody(
        Option.getOrElse(text, () => ""),
        secrets,
        longest,
      ),
    ),
  );
};

// ---------------------------------------------------------------------------
// Redirects
// ---------------------------------------------------------------------------

/**
 * Whether a `redirect: "manual"` response is a redirect. workerd and Node
 * return the real 3xx (`type: "default"`); a browser returns an
 * `"opaqueredirect"` with status 0. The status decides, and the opaque type
 * only adds to it.
 */
const isRedirect = (response: Response): boolean =>
  (response.status >= 300 && response.status <= 399) ||
  response.status === 0 ||
  response.type === "opaqueredirect";

/** Cancel a body without reading it; a body that fails to cancel is dropped all the same. */
const discardBody = (response: Response): Effect.Effect<void> => {
  const body = response.body;
  return body === null
    ? Effect.void
    : Effect.ignore(
        Effect.tryPromise({
          try: () => body.cancel(),
          catch: (cause) =>
            new AuthError({ message: "Failed to discard a redirect's body", cause }),
        }),
      );
};

/**
 * Fail a redirect as an {@link AuthError} carrying only its status. Its body is
 * cancelled unread, and its `Location` is never read, so nothing the redirect
 * names reaches the error or a second request.
 */
const rejectRedirect = (response: Response): Effect.Effect<never, AuthError> =>
  Effect.andThen(
    discardBody(response),
    Effect.fail(
      new AuthError({
        message: `Resend API responded with a redirect (status ${response.status}), which is not followed`,
        cause: { status: response.status },
      }),
    ),
  );

// ---------------------------------------------------------------------------
// Sender
// ---------------------------------------------------------------------------

/**
 * Build an {@link EmailSender} service backed by Resend's REST API. Every
 * failure (network, redirect, non-2xx response) surfaces as an
 * {@link AuthError}; a non-2xx one's `cause` carries the response `status` and
 * a `body` excerpt of at most {@link MAX_ERROR_BODY_CHARS} characters. The API
 * key is never included, even when the response echoes it. Redirects are
 * never followed: the request is sent with `redirect: "manual"` (workerd
 * rejects `"error"`), and any 3xx, status 0 or opaque redirect fails with
 * only its status, so the key goes to `baseUrl` only.
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

      const payload: typeof ResendPayloadJson.Type = {
        from: config.from,
        to: message.to,
        subject: rendered.subject,
        ...(rendered.html !== undefined && { html: rendered.html }),
        ...(rendered.text !== undefined && { text: rendered.text }),
      };

      const response = yield* Effect.tryPromise({
        try: (signal) =>
          doFetch(`${baseUrl}/emails`, {
            method: "POST",
            redirect: "manual",
            signal,
            headers: {
              Authorization: `Bearer ${Redacted.value(config.apiKey)}`,
              "Content-Type": "application/json",
            },
            body: encodePayload(payload),
          }),
        catch: (cause) => new AuthError({ message: "Failed to reach Resend API", cause }),
      });

      if (isRedirect(response)) return yield* rejectRedirect(response);
      if (!response.ok) {
        const body = yield* readErrorBody(response, [Redacted.value(config.apiKey)]);
        return yield* new AuthError({
          message: `Resend API request failed with status ${response.status}`,
          cause: { status: response.status, body },
        });
      }
      return yield* Effect.void;
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

/** Configuration for {@link layerConfig}: {@link ResendEmailSenderConfig} with the key read from `Config`. */
export interface ResendLayerConfig extends Omit<ResendEmailSenderConfig, "apiKey"> {
  /**
   * Where the API key comes from. Defaults to the `RESEND_API_KEY` variable,
   * which must be set and non-empty.
   */
  readonly apiKey?: Config.Config<Redacted.Redacted> | undefined;
}

/** `RESEND_API_KEY`, required and non-empty. */
const defaultApiKey: Config.Config<Redacted.Redacted> = Config.schema(
  Schema.Redacted(Schema.NonEmptyString),
  "RESEND_API_KEY",
);

/**
 * A `Layer` providing {@link EmailSender} backed by {@link resendEmailSender},
 * with the API key read from `Config` (`RESEND_API_KEY` by default).
 *
 * A missing or empty key fails the layer's construction with a `ConfigError`,
 * so the application fails at boot rather than dropping mail: a silently
 * unsent magic link, code or reset link is a lockout. There is no no-op
 * fallback; for development without a key, provide core's
 * `EmailSender.logging` instead, explicitly.
 *
 * @example
 * ```ts
 * import { layerConfig } from "@thomasfosterau/effect-auth-resend";
 *
 * // Fails at boot when RESEND_API_KEY is unset or empty.
 * const EmailLayer = layerConfig({ from: "App <noreply@example.com>" });
 * ```
 */
export const layerConfig = ({
  apiKey = defaultApiKey,
  ...config
}: ResendLayerConfig): Layer.Layer<EmailSender, Config.ConfigError> =>
  Layer.effect(
    EmailSender,
    Effect.map(apiKey, (key) => resendEmailSender({ ...config, apiKey: key })),
  );
