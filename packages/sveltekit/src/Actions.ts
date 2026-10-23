/**
 * Form actions for the credential flows: sign-in, sign-up and the other
 * forms that POST a credential to the auth handler and redirect on success.
 *
 * A SvelteKit form action has to do three things the auth handler can't do
 * for it:
 *
 * - **Relay `Set-Cookie`.** The handler's response sets the session cookie,
 *   but SvelteKit only sends cookies set through `event.cookies`. Headers on a
 *   thrown redirect are not passed through. {@link credentialAction} copies
 *   every `Set-Cookie` onto `event.cookies` before it redirects.
 * - **Redirect only to a validated target.** The "where to go next" value comes
 *   from the client, so it goes through the core's `safeRedirect`.
 * - **Tell failures apart.** A `401` means wrong credentials. A `429` means
 *   throttled, and before this helper a throttled sign-in read as "the form did
 *   nothing". Anything else means the service failed. Each gets its own
 *   {@link CredentialFailureKind} and status, so the form can say which.
 *
 * SvelteKit's `redirect` and `fail` are passed in, not imported, so this
 * package carries no SvelteKit dependency of its own.
 *
 * @module actions
 */
import { Array as Arr, DateTime, Option, Schema } from "effect";
import { safeRedirect } from "@thomasfosterau/effect-auth";

/**
 * The part of SvelteKit's `RequestEvent` a credential action reads and
 * writes. `@sveltejs/kit`'s `RequestEvent` satisfies it.
 *
 * @since 0.1.0
 * @category models
 */
export interface ActionEvent {
  readonly request: Request;
  readonly url: URL;
  readonly cookies: {
    readonly set: (name: string, value: string, options: CookieOptions) => void;
  };
}

/**
 * The cookie attributes relayed from a `Set-Cookie` header, in the shape
 * SvelteKit's `cookies.set` takes. `path` is always present: SvelteKit
 * requires it.
 *
 * @since 0.1.0
 * @category models
 */
export interface CookieOptions {
  path: string;
  domain?: string;
  maxAge?: number;
  expires?: Date;
  httpOnly?: boolean;
  secure?: boolean;
  sameSite?: "strict" | "lax" | "none";
  partitioned?: boolean;
}

/**
 * Why a credential action failed:
 *
 * - `invalid`: the handler answered `400` or `401` (bad input, or wrong
 *   credentials).
 * - `rate-limited`: the handler answered `429`.
 * - `unavailable`: anything else (a 5xx, or the call failing outright).
 *
 * @since 0.1.0
 * @category models
 */
export type CredentialFailureKind = "invalid" | "rate-limited" | "unavailable";

/**
 * What a failed credential action returns through SvelteKit's `fail`: the
 * kind, a message for the form, the seconds to wait for a `429` when the
 * handler said, and whatever form fields the action echoes back.
 *
 * @since 0.1.0
 * @category models
 */
export interface CredentialFailure<Fields> {
  readonly kind: CredentialFailureKind;
  readonly message: string;
  readonly retryAfterSeconds: number | null;
  readonly fields: Fields;
}

/**
 * SvelteKit's `redirect` and `fail`, passed in so this package doesn't import
 * `@sveltejs/kit`. Pass `{ redirect, fail }` from `@sveltejs/kit`.
 *
 * @since 0.1.0
 * @category models
 */
export interface Kit<Failure, Fields> {
  readonly redirect: (status: 303, location: string) => never;
  readonly fail: (status: number, data: CredentialFailure<Fields>) => Failure;
}

/**
 * Options for {@link credentialAction}.
 *
 * @since 0.1.0
 * @category models
 */
export interface CredentialActionOptions<Fields> {
  /**
   * Send the request to the auth handler: the service binding's `fetch`, or
   * the in-process handler.
   */
  readonly fetch: (request: Request) => Promise<Response>;
  /** The auth endpoint to POST to, as an absolute URL (for example `https://auth.internal/api/auth/sign-in`). */
  readonly endpoint: string;
  /** The JSON body to send, built from the submitted form. */
  readonly body: (form: FormData) => Schema.Json;
  /** The form fields to echo back on failure (never the password). */
  readonly fields: (form: FormData) => Fields;
  /** The query parameter that carries the post-sign-in target. Default `redirect`. */
  readonly redirectParam?: string | undefined;
  /** Where to go when the target is missing or unsafe. */
  readonly fallback: string;
  /** Override the message per failure kind. */
  readonly messages?: Partial<Record<CredentialFailureKind, string>> | undefined;
}

const defaultMessages: Record<CredentialFailureKind, string> = {
  invalid: "Invalid email or password.",
  "rate-limited": "Too many attempts. Please wait and try again.",
  unavailable: "Sign-in is unavailable right now. Please try again.",
};

/** The status the form failure is reported with, per kind. */
const failureStatus: Record<CredentialFailureKind, number> = {
  invalid: 400,
  "rate-limited": 429,
  unavailable: 503,
};

/** Serializes the request body as JSON. */
const encodeJson = Schema.encodeSync(Schema.fromJsonString(Schema.Json));

const kindOf = (status: number): CredentialFailureKind =>
  status === 429 ? "rate-limited" : status === 400 || status === 401 ? "invalid" : "unavailable";

/** `Retry-After` in seconds, when it is a non-negative integer. */
const retryAfterSeconds = (response: Response | null): number | null => {
  const header = response?.headers.get("retry-after") ?? null;
  if (header === null || !/^\d+$/u.test(header.trim())) return null;
  return Number(header.trim());
};

const sameSiteOf = (value: string): CookieOptions["sameSite"] | undefined => {
  const lower = value.toLowerCase();
  return lower === "strict" || lower === "lax" || lower === "none" ? lower : undefined;
};

/**
 * Parse one `Set-Cookie` header into a name, a value and SvelteKit cookie
 * options. Returns `None` for a header with no `name=` pair.
 *
 * @since 0.1.0
 * @category cookies
 */
export const parseSetCookie = (
  header: string,
): Option.Option<{
  readonly name: string;
  readonly value: string;
  readonly options: CookieOptions;
}> => {
  const [pair = "", ...attributes] = header.split(";");
  const separator = pair.indexOf("=");
  if (separator <= 0) return Option.none();
  const name = pair.slice(0, separator).trim();
  const value = pair.slice(separator + 1).trim();
  const options: CookieOptions = { path: "/" };
  Arr.forEach(attributes, (attribute) => {
    const [rawKey = "", ...rest] = attribute.split("=");
    const key = rawKey.trim().toLowerCase();
    const attributeValue = rest.join("=").trim();
    if (key === "path" && attributeValue !== "") options.path = attributeValue;
    else if (key === "domain" && attributeValue !== "") options.domain = attributeValue;
    else if (key === "max-age" && /^-?\d+$/u.test(attributeValue)) {
      options.maxAge = Number(attributeValue);
    } else if (key === "expires") {
      Option.map(DateTime.make(attributeValue), (expires) => {
        options.expires = DateTime.toDateUtc(expires);
      });
    } else if (key === "httponly") options.httpOnly = true;
    else if (key === "secure") options.secure = true;
    else if (key === "partitioned") options.partitioned = true;
    else if (key === "samesite") {
      const sameSite = sameSiteOf(attributeValue);
      if (sameSite !== undefined) options.sameSite = sameSite;
    }
  });
  // SvelteKit defaults `httpOnly` and `secure` to true when they are omitted,
  // so state their absence explicitly to keep the handler's choice.
  options.httpOnly ??= false;
  options.secure ??= false;
  return Option.some({ name, value, options });
};

/** Copy every `Set-Cookie` the handler sent onto `event.cookies`. */
const relayCookies = (event: ActionEvent, response: Response): void => {
  Arr.forEach(response.headers.getSetCookie(), (header) => {
    Option.map(parseSetCookie(header), ({ name, value, options }) =>
      event.cookies.set(name, value, options),
    );
  });
};

/**
 * Build a form action for a credential flow.
 *
 * The action POSTs the form to `endpoint` as JSON, forwarding the browser's
 * `Origin`, `User-Agent` and `X-Forwarded-For` so the handler's CSRF check and
 * rate limits see the real client. On a 2xx it relays the `Set-Cookie`
 * headers and redirects (303) to the validated target. Otherwise it returns
 * `fail(status, CredentialFailure)`, with a status per
 * {@link CredentialFailureKind}.
 *
 * @example
 * ```ts
 * import { deepStrictEqual } from "node:assert";
 * import { credentialAction } from "@thomasfosterau/effect-auth-sveltekit";
 *
 * const kit = {
 *   redirect: (status: 303, location: string): never => {
 *     throw { status, location };
 *   },
 *   fail: <Data>(status: number, data: Data) => ({ status, data }),
 * };
 *
 * const signIn = credentialAction(kit, {
 *   fetch: async () => new Response(null, { status: 429, headers: { "retry-after": "30" } }),
 *   endpoint: "https://auth.internal/api/auth/sign-in",
 *   body: (form) => ({
 *     email: String(form.get("email") ?? ""),
 *     password: String(form.get("password") ?? ""),
 *   }),
 *   fields: (form) => ({ email: String(form.get("email") ?? "") }),
 *   fallback: "/",
 * });
 *
 * const form = new FormData();
 * form.set("email", "ada@example.com");
 * form.set("password", "hunter2");
 * const result = await signIn({
 *   request: new Request("https://app.example/login", { method: "POST", body: form }),
 *   url: new URL("https://app.example/login?redirect=/dashboard"),
 *   cookies: { set: () => undefined },
 * });
 * deepStrictEqual(result, {
 *   status: 429,
 *   data: {
 *     kind: "rate-limited",
 *     message: "Too many attempts. Please wait and try again.",
 *     retryAfterSeconds: 30,
 *     fields: { email: "ada@example.com" },
 *   },
 * });
 * ```
 *
 * @since 0.1.0
 * @category actions
 */
export const credentialAction =
  <Failure, Fields>(kit: Kit<Failure, Fields>, options: CredentialActionOptions<Fields>) =>
  async (event: ActionEvent): Promise<Failure> => {
    const form = await event.request.formData();
    const forwarded = new Headers({ "content-type": "application/json" });
    Arr.forEach(["origin", "user-agent", "x-forwarded-for", "cf-connecting-ip"], (name) => {
      const value = event.request.headers.get(name);
      if (value !== null) forwarded.set(name, value);
    });
    const response = await options
      .fetch(
        new Request(options.endpoint, {
          method: "POST",
          headers: forwarded,
          body: encodeJson(options.body(form)),
        }),
      )
      .then(
        (value) => value,
        () => null,
      );

    if (response !== null && response.ok) {
      relayCookies(event, response);
      const target = event.url.searchParams.get(options.redirectParam ?? "redirect");
      return kit.redirect(303, safeRedirect(target, options.fallback));
    }

    const kind = response === null ? "unavailable" : kindOf(response.status);
    const failure: CredentialFailure<Fields> = {
      kind,
      message: options.messages?.[kind] ?? defaultMessages[kind],
      retryAfterSeconds: kind === "rate-limited" ? retryAfterSeconds(response) : null,
      fields: options.fields(form),
    };
    return kit.fail(failureStatus[kind], failure);
  };
