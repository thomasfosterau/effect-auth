/**
 * The SvelteKit `handle` hook: resolve the session once, before any `load`
 * runs, and keep a page rendered for a signed-in viewer out of shared caches.
 *
 * ### Order matters
 *
 * The hook authenticates first, puts the result on `event.locals.auth`,
 * renders, and only then sets the cache headers. Cache-control has to see the
 * resolved viewer, so a response rendered for a signed-in viewer is forced to
 * `private, no-store`, whatever the route asked for. A hook that sets cache
 * headers before authenticating ends up caching a page rendered for an admin
 * and serving it to anonymous visitors.
 *
 * ### Resolution
 *
 * Resolution goes through the core's `SessionResolution`, so the cookieless
 * skip, the fail-open or fail-closed choice and the outcome metric are the
 * ones every other edge uses. The app supplies the lookup itself: the
 * in-process `SessionService`, or `Http.RemoteSession` over a service binding.
 *
 * @module handle
 */
import { type Cause, Effect, Option } from "effect";
import {
  SessionResolution,
  type SessionCookies,
  type SessionWithUser,
} from "@thomasfosterau/effect-auth";

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
  readonly cookies: { readonly get: (name: string) => string | undefined };
  readonly locals: object;
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
export type FailurePolicy =
  | { readonly mode: "closed" }
  | {
      readonly mode: "open";
      readonly onDegraded: (cause: Cause.Cause<unknown>) => Effect.Effect<void>;
    };

/**
 * Options for {@link handle}.
 *
 * @since 0.1.0
 * @category models
 */
export interface HandleOptions {
  /** The session cookie's naming, as the auth handler was configured. */
  readonly cookies?: SessionCookies.SessionCookieNaming | undefined;
  /**
   * Look the session up for this request: `Option.none()` when nobody is
   * signed in. Runs only when the request carries a credential.
   */
  readonly lookup: (request: Request) => Effect.Effect<Option.Option<SessionWithUser>, unknown>;
  /** What a lookup fault does. Required: neither direction is a safe default. */
  readonly failure: FailurePolicy;
}

/** The `Cache-Control` a response rendered for a signed-in viewer is forced to. */
export const PRIVATE_CACHE_CONTROL = "private, no-store";

/** A copy of `response` whose headers may be changed (a fetched response's are immutable). */
const withPrivateCache = (response: Response): Response => {
  const copy = new Response(response.body, response);
  copy.headers.set("cache-control", PRIVATE_CACHE_CONTROL);
  return copy;
};

const resolveSession = (
  event: HandleEvent,
  options: HandleOptions,
): Effect.Effect<SessionResolution.SessionResolutionResult, unknown> => {
  const credential = SessionResolution.detectCredential(
    SessionResolution.fromCookies(event.cookies, event.request.headers),
    options.cookies,
  );
  const resolve = options.lookup(event.request);
  const failure = options.failure;
  return failure.mode === "open"
    ? SessionResolution.resolveFailOpen({ credential, resolve, onDegraded: failure.onDegraded })
    : SessionResolution.resolve({ credential, resolve });
};

/**
 * Build the `handle` hook.
 *
 * It resolves the session, sets `event.locals.auth` ({@link LocalsAuth}),
 * renders the route, and forces `Cache-Control: private, no-store` on the
 * response when a viewer is signed in. Compose it first in `sequence(...)`,
 * so every later hook and every `load` sees the resolved viewer.
 *
 * @example
 * ```ts
 * import { strictEqual } from "node:assert";
 * import { Effect, Option } from "effect";
 * import { handle } from "@thomasfosterau/effect-auth-sveltekit";
 *
 * const hook = handle({
 *   lookup: () => Effect.succeed(Option.none()),
 *   failure: { mode: "closed" },
 * });
 *
 * const event = {
 *   request: new Request("https://app.example/"),
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
  (options: HandleOptions) =>
  async <Event extends HandleEvent>(input: HandleInput<Event>): Promise<Response> => {
    const { session, outcome } = await Effect.runPromise(resolveSession(input.event, options));
    const auth: LocalsAuth = { session: Option.getOrNull(session), outcome };
    Object.assign(input.event.locals, { auth });
    const response = await input.resolve(input.event);
    return auth.session === null ? response : withPrivateCache(response);
  };
