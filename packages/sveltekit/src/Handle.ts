/**
 * The SvelteKit `handle` hook: resolves the session once through the core's
 * `SessionResolution`, before any `load`, puts it on `event.locals.auth`, and
 * only after rendering sets the cache headers, forcing `private, no-store` for
 * a signed-in viewer. The app supplies the lookup.
 *
 * @module handle
 */
import type * as Cause from "effect/Cause";
import * as Effect from "effect/Effect";
import * as Arr from "effect/Array";
import * as Option from "effect/Option";
import { SessionResolution, type SessionCookies } from "@thomasfosterau/effect-auth";
import { type SessionWithUser } from "@thomasfosterau/effect-auth/Types";

/**
 * The part of SvelteKit's `RequestEvent` the hook reads and writes.
 * `@sveltejs/kit`'s `RequestEvent` satisfies it, so this package needs no
 * dependency on SvelteKit itself.
 *
 * @since 0.1.0
 * @category models
 */
export interface HandleEvent {
  readonly request: Request;
  /** The client's address as the SvelteKit adapter knows it, for the lookup. */
  readonly getClientAddress: () => string;
  readonly cookies: { readonly get: (name: string) => string | undefined };
  readonly locals: object;
}

/**
 * A lookup's answer when it carries `Set-Cookie` lines as well as the
 * session: what `Http.RemoteSession`'s `read` answers. The hook replays the
 * lines on the response, so a refreshed cache cookie or the clearing of a
 * stale one reaches the browser.
 *
 * @since 0.4.0
 * @category models
 */
export interface SessionLookup {
  readonly session: Option.Option<SessionWithUser>;
  readonly setCookie: ReadonlyArray<string>;
}

/**
 * The `handle` input, structurally, as SvelteKit's `Handle` type passes it.
 *
 * @since 0.1.0
 * @category models
 */
export interface HandleInput<Event extends HandleEvent> {
  readonly event: Event;
  readonly resolve: (event: Event) => Response | Promise<Response>;
}

/**
 * What the hook puts on `event.locals.auth`. Declare it in `App.Locals`:
 *
 * ```ts skip-type-checking
 * declare global {
 *   namespace App {
 *     interface Locals {
 *       auth: import("@thomasfosterau/effect-auth-sveltekit").LocalsAuth;
 *     }
 *   }
 * }
 * ```
 *
 * @since 0.1.0
 * @category models
 */
export interface LocalsAuth {
  /** The signed-in viewer's session and user, or `null` for anonymous. */
  readonly session: SessionWithUser | null;
  /** How resolution went: `skipped`, `resolved`, `anonymous` or `degraded`. */
  readonly outcome: SessionResolution.AuthOutcome;
}

/**
 * What a session-lookup fault does to the request.
 *
 * - `closed`: the fault fails the request.
 * - `open`: the request continues as anonymous, and `onDegraded` hears about
 *   it. Only safe when anonymous is the lower-privilege outcome (see
 *   `SessionResolution.resolveFailOpen`).
 *
 * @since 0.1.0
 * @category models
 */
export type FailurePolicy<E = unknown> =
  | { readonly mode: "closed" }
  | {
      readonly mode: "open";
      readonly onDegraded: (cause: Cause.Cause<E>) => Effect.Effect<void>;
    };

/**
 * Options for {@link handle}.
 *
 * @since 0.1.0
 * @category models
 */
export interface HandleOptions<E = unknown> {
  /** The session cookie's naming, as the auth handler was configured. */
  readonly cookies?: SessionCookies.SessionCookieNaming;
  /**
   * Look the session up for this request: `Option.none()` when nobody is
   * signed in, or a {@link SessionLookup} carrying `Set-Cookie` lines to
   * replay. Runs only when the request carries a credential. Over
   * `Http.RemoteSession`, pass the client address on:
   * `(request, event) => auth.read(request, { clientAddress: event.getClientAddress() })`.
   */
  readonly lookup: (
    request: Request,
    event: HandleEvent,
  ) => Effect.Effect<Option.Option<SessionWithUser> | SessionLookup, E>;
  /** What a lookup fault does. Required: neither direction is a safe default. */
  readonly failure: FailurePolicy<E>;
}

/** The `Cache-Control` a response rendered for a signed-in viewer is forced to. */
export const PRIVATE_CACHE_CONTROL = "private, no-store";

/** A copy of `response` whose headers may be changed (a fetched response's are immutable). */
const withPrivateCache = (response: Response): Response => {
  const copy = new Response(response.body, response);
  copy.headers.set("cache-control", PRIVATE_CACHE_CONTROL);
  return copy;
};

const noCookies: SessionLookup = { session: Option.none(), setCookie: [] };

const asLookup = (value: Option.Option<SessionWithUser> | SessionLookup): SessionLookup =>
  Option.isOption(value) ? { session: value, setCookie: [] } : value;

const resolveSession = <E>(
  event: HandleEvent,
  options: HandleOptions<E>,
): Effect.Effect<SessionResolution.ResolveWithResult<SessionLookup>, E> => {
  const credential = SessionResolution.detectCredential(
    SessionResolution.fromCookies(event.cookies, event.request.headers),
    options.cookies,
  );
  const resolve = Effect.map(options.lookup(event.request, event), asLookup);
  const failure = options.failure;
  return Effect.map(
    failure.mode === "open"
      ? SessionResolution.resolveWithFailOpen({
          credential,
          resolve,
          session: (lookup) => lookup.session,
          empty: noCookies,
          onDegraded: failure.onDegraded,
        })
      : SessionResolution.resolveWith({
          credential,
          resolve,
          session: (lookup) => lookup.session,
          empty: noCookies,
        }),
    // A machine caller is never handed a cookie (the core's relay rule).
    (result) =>
      credential.hasApiKey || credential.hasBearer
        ? { ...result, value: { ...result.value, setCookie: [] } }
        : result,
  );
};

/** The response with the lookup's `Set-Cookie` lines appended, kept out of shared caches. */
const withLookupCookies = (response: Response, setCookie: ReadonlyArray<string>): Response => {
  const copy = new Response(response.body, response);
  setCookie.forEach((line) => copy.headers.append("set-cookie", line));
  copy.headers.set("cache-control", PRIVATE_CACHE_CONTROL);
  return copy;
};

/**
 * Build the `handle` hook.
 *
 * It resolves the session, sets `event.locals.auth` ({@link LocalsAuth}),
 * renders the route, and forces `Cache-Control: private, no-store` on the
 * response when a viewer is signed in or the lookup sent `Set-Cookie` lines,
 * which it appends to the response (never for an API-key or bearer caller). Compose it first in `sequence(...)`,
 * so every later hook and every `load` sees the resolved viewer.
 *
 * @example
 * ```ts
 * import { strictEqual } from "node:assert";
 * import { Effect } from "effect";
 * import * as Option from "effect/Option";
 * import { handle } from "@thomasfosterau/effect-auth-sveltekit/Handle";
 *
 * const hook = handle({
 *   lookup: () => Effect.succeed(Option.none()),
 *   failure: { mode: "closed" },
 * });
 *
 * const event = {
 *   request: new Request("https://app.example/"),
 *   getClientAddress: () => "203.0.113.9",
 *   cookies: { get: () => undefined },
 *   locals: {},
 * };
 * const response = await hook({ event, resolve: () => new Response("ok") });
 * strictEqual(await response.text(), "ok");
 * ```
 *
 * @since 0.1.0
 * @category hooks
 */
export const handle =
  <E>(options: HandleOptions<E>) =>
  async <Event extends HandleEvent>(input: HandleInput<Event>): Promise<Response> => {
    const { value, outcome } = await Effect.runPromise(resolveSession(input.event, options));
    const auth: LocalsAuth = { session: Option.getOrNull(value.session), outcome };
    Object.assign(input.event.locals, { auth });
    const response = await input.resolve(input.event);
    if (Arr.isReadonlyArrayNonEmpty(value.setCookie))
      return withLookupCookies(response, value.setCookie);
    return auth.session === null ? response : withPrivateCache(response);
  };
