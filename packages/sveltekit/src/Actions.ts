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
 * - **Tell "signed in" from "not yet".** A `202` issued no session: a second
 *   factor is pending, or the address must be verified first. The action
 *   returns a {@link CredentialPending} instead of redirecting, so the form can
 *   move to its second-factor or check-your-inbox step.
 *
 * SvelteKit's `redirect` and `fail` are passed in, not imported, so this
 * package carries no SvelteKit dependency of its own.
 *
 * @module actions
 */
import { DateTime } from "effect";
import * as Arr from "effect/Array";
import * as Option from "effect/Option";
import * as Schema from "effect/Schema";
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
 * What a credential action returns, as a successful action result, when the
 * handler answered `202 Accepted`: it took the credential but issued no
 * session. Either `secondFactor` is the challenge to redeem (`POST
 * /second-factor-challenges/verifications`, citing `token`), or it is `null`
 * and `needsEmailVerification` says the address must be verified first (a
 * sign-up under `antiEnumeration` always answers this way). `fields` is what
 * {@link CredentialActionOptions.fields} echoes back.
 *
 * @since 0.1.0
 * @category models
 */
export interface CredentialPending<Fields> {
  readonly kind: "pending";
  readonly secondFactor: {
    /** The challenge token: the id of the `second-factor-challenges` resource. */
    readonly token: string;
    /** When the challenge lapses, as the handler's ISO 8601 timestamp. */
    readonly expiresAt: string;
  } | null;
  readonly needsEmailVerification: boolean;
  readonly fields: Fields;
}

/** The `202` body: the JSON:API `PendingDocument` of the core's HTTP API. */
const PendingBody = Schema.fromJsonString(
  Schema.Struct({
    data: Schema.optionalKey(
      Schema.Struct({
        type: Schema.Literal("second-factor-challenges"),
        id: Schema.String,
        attributes: Schema.Struct({ expiresAt: Schema.String }),
      }),
    ),
    meta: Schema.Struct({ needsEmailVerification: Schema.Boolean }),
  }),
);
const decodePending = Schema.decodeUnknownOption(PendingBody);

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
 * Options for {@link submitCredential} and the helpers built on it, for a
 * credential submitted as an `Input`: the submitted `FormData` for a form
 * action, or whatever a remote function receives.
 *
 * @since 0.2.0
 * @category models
 */
export interface CredentialRequestOptions<Input, Fields> {
  /**
   * Send the request to the auth handler: the service binding's `fetch`, or
   * the in-process handler.
   */
  readonly fetch: (request: Request) => Promise<Response>;
  /** The auth endpoint to POST to, as an absolute URL (for example `https://auth.internal/api/auth/sessions`). */
  readonly endpoint: string;
  /**
   * The body to send, built from the submitted input: for the auth handler's
   * credential flows, a JSON:API document (`POST /sessions` takes a `sessions`
   * document whose `credential` attribute names the method).
   */
  readonly body: (input: Input) => Schema.Json;
  /**
   * The body's media type. Default `application/vnd.api+json`, what the auth
   * handler's credential flows accept; pass `application/json` for an endpoint
   * that takes plain JSON.
   */
  readonly contentType?: string | undefined;
  /** The input fields to echo back on failure (never the password). */
  readonly fields: (input: Input) => Fields;
  /**
   * The post-sign-in target the client asked for, before validation. Default:
   * the {@link CredentialRequestOptions.redirectParam} query parameter of
   * `event.url`. A remote function's event is the remote call's, not the
   * page's, so read the target from the input there (a hidden field, say).
   * Whatever it returns goes through `safeRedirect`.
   */
  readonly target?: ((input: Input, event: ActionEvent) => string | null) | undefined;
  /** The query parameter that carries the post-sign-in target. Default `redirect`. */
  readonly redirectParam?: string | undefined;
  /** Where to go when the target is missing or unsafe. */
  readonly fallback: string;
  /** Override the message per failure kind. */
  readonly messages?: Partial<Record<CredentialFailureKind, string>> | undefined;
}

/**
 * Options for {@link credentialAction}: {@link CredentialRequestOptions} over
 * the submitted `FormData`.
 *
 * @since 0.1.0
 * @category models
 */
export type CredentialActionOptions<Fields> = CredentialRequestOptions<FormData, Fields>;

/**
 * The handler issued a session: its `Set-Cookie` headers are already relayed
 * onto `event.cookies`, and `location` is the validated target to go to.
 *
 * @since 0.2.0
 * @category models
 */
export interface CredentialSignedIn {
  readonly kind: "signed-in";
  readonly location: string;
}

/**
 * The handler refused the credential or failed: the form failure, and the
 * status a form action reports it with (one per {@link CredentialFailureKind}).
 *
 * @since 0.2.0
 * @category models
 */
export interface CredentialRejected<Fields> {
  readonly kind: "failed";
  readonly status: number;
  readonly failure: CredentialFailure<Fields>;
}

/**
 * What {@link submitCredential} answers: a session (cookies relayed), a
 * pending next step (no session yet), or a failure.
 *
 * @since 0.2.0
 * @category models
 */
export type CredentialResult<Fields> =
  | CredentialSignedIn
  | CredentialPending<Fields>
  | CredentialRejected<Fields>;

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

/** How each `Set-Cookie` attribute lands in SvelteKit's options; unknown attributes are dropped. */
const cookieAttributes: Readonly<Record<string, (options: CookieOptions, value: string) => void>> =
  {
    path: (options, value) => {
      if (value !== "") options.path = value;
    },
    domain: (options, value) => {
      if (value !== "") options.domain = value;
    },
    "max-age": (options, value) => {
      if (/^-?\d+$/u.test(value)) options.maxAge = Number(value);
    },
    expires: (options, value) => {
      Option.map(DateTime.make(value), (expires) => {
        options.expires = DateTime.toDateUtc(expires);
      });
    },
    httponly: (options) => {
      options.httpOnly = true;
    },
    secure: (options) => {
      options.secure = true;
    },
    partitioned: (options) => {
      options.partitioned = true;
    },
    samesite: (options, value) => {
      const sameSite = sameSiteOf(value);
      if (sameSite !== undefined) options.sameSite = sameSite;
    },
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
    cookieAttributes[rawKey.trim().toLowerCase()]?.(options, rest.join("=").trim());
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
 * Submit a credential to the auth handler on behalf of one request: the core
 * the form-action and remote-function helpers share.
 *
 * It POSTs `options.body(input)` to `endpoint`, forwarding the browser's
 * `Origin`, `User-Agent` and `X-Forwarded-For` (and `CF-Connecting-IP`) so the
 * handler's CSRF check and rate limits see the real client. On a `202` (no
 * session issued: a second factor is pending, or the address must be verified
 * first) it answers {@link CredentialPending}; a `202` whose body is not the
 * handler's pending document counts as `unavailable`. On any other 2xx it
 * relays the `Set-Cookie` headers onto `event.cookies` and answers
 * {@link CredentialSignedIn} with the `safeRedirect`-validated target.
 * Otherwise it answers {@link CredentialRejected}. It never throws for the
 * handler's answer: a failing `fetch` is `unavailable` too.
 *
 * @since 0.2.0
 * @category actions
 */
export const submitCredential = async <Input, Fields>(
  event: ActionEvent,
  input: Input,
  options: CredentialRequestOptions<Input, Fields>,
): Promise<CredentialResult<Fields>> => {
  const forwarded = new Headers({
    "content-type": options.contentType ?? "application/vnd.api+json",
  });
  Arr.forEach(["origin", "user-agent", "x-forwarded-for", "cf-connecting-ip"], (name) => {
    const value = event.request.headers.get(name);
    if (value !== null) forwarded.set(name, value);
  });
  const response = await options
    .fetch(
      new Request(options.endpoint, {
        method: "POST",
        headers: forwarded,
        body: encodeJson(options.body(input)),
      }),
    )
    .then(
      (value) => value,
      () => null,
    );

  const pending =
    response?.status === 202 ? decodePending(await response.text().catch(() => "")) : Option.none();
  if (Option.isSome(pending)) {
    const { data, meta } = pending.value;
    return {
      kind: "pending",
      secondFactor:
        data === undefined ? null : { token: data.id, expiresAt: data.attributes.expiresAt },
      needsEmailVerification: meta.needsEmailVerification,
      fields: options.fields(input),
    };
  }

  if (response !== null && response.ok && response.status !== 202) {
    relayCookies(event, response);
    const target =
      options.target === undefined
        ? event.url.searchParams.get(options.redirectParam ?? "redirect")
        : options.target(input, event);
    return { kind: "signed-in", location: safeRedirect(target, options.fallback) };
  }

  const kind = response === null ? "unavailable" : kindOf(response.status);
  return {
    kind: "failed",
    status: failureStatus[kind],
    failure: {
      kind,
      message: options.messages?.[kind] ?? defaultMessages[kind],
      retryAfterSeconds: kind === "rate-limited" ? retryAfterSeconds(response) : null,
      fields: options.fields(input),
    },
  };
};

/**
 * Build a form action for a credential flow.
 *
 * The action submits the form through {@link submitCredential}. On a session
 * it redirects (303) to the validated target, with the `Set-Cookie` headers
 * relayed. On a `202` (no session issued: a second factor is pending, or the
 * address must be verified first) it returns the {@link CredentialPending}
 * without redirecting. Otherwise it returns `fail(status, CredentialFailure)`,
 * with a status per {@link CredentialFailureKind}.
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
 *   endpoint: "https://auth.internal/api/auth/sessions",
 *   // Sign in with a password credential: a `sessions` document.
 *   body: (form) => ({
 *     data: {
 *       type: "sessions",
 *       attributes: {
 *         credential: {
 *           method: "password",
 *           email: String(form.get("email") ?? ""),
 *           password: String(form.get("password") ?? ""),
 *         },
 *       },
 *     },
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
  async (event: ActionEvent): Promise<Failure | CredentialPending<Fields>> => {
    const result = await submitCredential(event, await event.request.formData(), options);
    if (result.kind === "signed-in") return kit.redirect(303, result.location);
    return result.kind === "pending" ? result : kit.fail(result.status, result.failure);
  };

/**
 * SvelteKit's `getRequestEvent` (from `$app/server`), passed in so this
 * package doesn't import SvelteKit: what a remote function reads its request
 * event from.
 *
 * @since 0.2.0
 * @category models
 */
export interface RemoteKit {
  readonly getRequestEvent: () => ActionEvent;
}

/**
 * {@link RemoteKit} plus SvelteKit's `redirect` (from `@sveltejs/kit`), for a
 * remote `form()`, which may redirect.
 *
 * @since 0.2.0
 * @category models
 */
export interface RemoteFormKit extends RemoteKit {
  readonly redirect: (status: 303, location: string) => never;
}

/**
 * Build the handler of a SvelteKit remote `form()` for a credential flow.
 *
 * The same submission as {@link credentialAction}, through
 * {@link submitCredential}, with a remote function's envelope: the event comes
 * from `getRequestEvent()`, a session redirects (303) to the validated target,
 * and everything else is the form's result (`form.result` on the page): the
 * {@link CredentialPending} next step, or the {@link CredentialFailure}, whose
 * `kind` tells wrong credentials (`invalid`) from throttling (`rate-limited`)
 * and faults (`unavailable`). `Input` is whatever the remote form hands its
 * handler (`FormData`, or the validated object of a schema'd form).
 *
 * The event of a remote call is not the page's, so pass
 * {@link CredentialRequestOptions.target} to read the post-sign-in target from
 * the input.
 *
 * @example
 * ```ts
 * import { deepStrictEqual, rejects } from "node:assert";
 * import { credentialForm } from "@thomasfosterau/effect-auth-sveltekit";
 *
 * const relayed: Array<string> = [];
 * const kit = {
 *   // `getRequestEvent` from `$app/server` and `redirect` from `@sveltejs/kit`.
 *   getRequestEvent: () => ({
 *     request: new Request("https://app.example/_app/remote/sign-in", { method: "POST" }),
 *     url: new URL("https://app.example/_app/remote/sign-in"),
 *     cookies: { set: (name: string) => void relayed.push(name) },
 *   }),
 *   redirect: (status: 303, location: string): never => {
 *     throw { status, location };
 *   },
 * };
 *
 * const handler = (response: Response) =>
 *   credentialForm(kit, {
 *     fetch: async () => response,
 *     endpoint: "https://auth.internal/api/auth/sessions",
 *     body: (form: FormData) => ({
 *       data: {
 *         type: "sessions",
 *         attributes: {
 *           credential: {
 *             method: "password",
 *             email: String(form.get("email") ?? ""),
 *             password: String(form.get("password") ?? ""),
 *           },
 *         },
 *       },
 *     }),
 *     fields: (form) => ({ email: String(form.get("email") ?? "") }),
 *     target: (form) => String(form.get("redirect") ?? ""),
 *     fallback: "/",
 *   });
 *
 * const form = new FormData();
 * form.set("email", "ada@example.com");
 * form.set("password", "hunter2");
 * form.set("redirect", "/dashboard");
 *
 * // In `sign-in.remote.ts`: `export const signIn = form(handler(...))`.
 * const session = new Headers({ "set-cookie": "__Host-session=tok; Path=/; HttpOnly; Secure" });
 * await rejects(handler(new Response("{}", { status: 201, headers: session }))(form), {
 *   status: 303,
 *   location: "/dashboard",
 * });
 * deepStrictEqual(relayed, ["__Host-session"]);
 *
 * deepStrictEqual(await handler(new Response(null, { status: 401 }))(form), {
 *   kind: "invalid",
 *   message: "Invalid email or password.",
 *   retryAfterSeconds: null,
 *   fields: { email: "ada@example.com" },
 * });
 * ```
 *
 * @since 0.2.0
 * @category remote functions
 */
export const credentialForm =
  <Input, Fields>(kit: RemoteFormKit, options: CredentialRequestOptions<Input, Fields>) =>
  async (input: Input): Promise<CredentialPending<Fields> | CredentialFailure<Fields>> => {
    const result = await submitCredential(kit.getRequestEvent(), input, options);
    if (result.kind === "signed-in") return kit.redirect(303, result.location);
    return result.kind === "pending" ? result : result.failure;
  };

/**
 * Build the handler of a SvelteKit remote `command()` for a credential flow.
 *
 * A command cannot redirect, so it answers the whole {@link CredentialResult}:
 * on `signed-in` the cookies are already set, and the caller navigates to
 * `location` itself (`goto(result.location)`); `pending` and `failed` are as
 * for {@link credentialForm}.
 *
 * @example
 * ```ts
 * import { deepStrictEqual } from "node:assert";
 * import { credentialCommand } from "@thomasfosterau/effect-auth-sveltekit";
 *
 * const signIn = credentialCommand(
 *   {
 *     getRequestEvent: () => ({
 *       request: new Request("https://app.example/_app/remote/sign-in", { method: "POST" }),
 *       url: new URL("https://app.example/_app/remote/sign-in"),
 *       cookies: { set: () => undefined },
 *     }),
 *   },
 *   {
 *     fetch: async () => new Response(null, { status: 429, headers: { "retry-after": "30" } }),
 *     endpoint: "https://auth.internal/api/auth/sessions",
 *     body: (input: { readonly email: string; readonly password: string }) => ({
 *       data: { type: "sessions", attributes: { credential: { method: "password", ...input } } },
 *     }),
 *     fields: (input) => ({ email: input.email }),
 *     fallback: "/",
 *   },
 * );
 *
 * deepStrictEqual(await signIn({ email: "ada@example.com", password: "hunter2" }), {
 *   kind: "failed",
 *   status: 429,
 *   failure: {
 *     kind: "rate-limited",
 *     message: "Too many attempts. Please wait and try again.",
 *     retryAfterSeconds: 30,
 *     fields: { email: "ada@example.com" },
 *   },
 * });
 * ```
 *
 * @since 0.2.0
 * @category remote functions
 */
export const credentialCommand =
  <Input, Fields>(kit: RemoteKit, options: CredentialRequestOptions<Input, Fields>) =>
  (input: Input): Promise<CredentialResult<Fields>> =>
    submitCredential(kit.getRequestEvent(), input, options);
