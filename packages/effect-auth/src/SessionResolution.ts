/**
 * Session resolution at an application's **own** edge — before any effect-auth
 * handler runs.
 *
 * An app that resolves the session itself (a SvelteKit `hooks.server.ts`, a
 * Worker that calls an auth service binding, an API gateway in front of
 * `Http.make`) has to answer three questions this module owns:
 *
 * 1. **Does this request carry a credential at all?** If not, resolution
 *    cannot succeed, so skip it. On a hot path this is the largest read-path
 *    win available — see {@link detectCredential} / {@link hasSessionCredential}.
 * 2. **What happens when resolution faults?** Fail open or fail closed. Both
 *    are here, both named, neither a default — see {@link resolveFailOpen}.
 * 3. **What just happened, for observability?** One derivation of one
 *    {@link AuthOutcome}, emitted as a metric and a span attribute by the
 *    resolver itself — see below.
 *
 * ### Why the outcome is not the caller's to derive
 *
 * Two edges that classify the same fault independently will eventually
 * disagree — one Worker logging `degraded` where another logs `skipped` for an
 * identical unreachable binding is the failure mode this exists to prevent.
 * So {@link resolve} and {@link resolveFailOpen} return the outcome *with* the
 * session, and record it themselves. There is no `deriveAuthOutcome` for a
 * caller to reimplement, and no counter to wire up: Effect's metrics and
 * tracing are no-ops until a backend is in context, so the instrumentation is
 * free when unused.
 *
 * ### Credential predicates take plain inputs
 *
 * Nothing here needs an `HttpServerRequest`, an `HttpClient` or a running
 * Effect HTTP stack. The predicates read a {@link CredentialSource}, which a
 * raw `Headers`, a plain header record, or a SvelteKit-style cookie jar all
 * satisfy — because the callers that need them most run before any of that
 * exists.
 *
 * @module session-resolution
 */
import { Cause, Effect, Option } from "effect";
import * as Observability from "./Observability.ts";
import * as SessionCookies from "./SessionCookies.ts";
import type * as Types from "./Types.ts";

/**
 * The four outcomes of a resolution attempt. Re-exported from `Observability`,
 * where it sits beside its counter; this is the name to import.
 *
 * @since 1.0.0
 * @category models
 */
export type AuthOutcome = Observability.AuthOutcome;

// ---------------------------------------------------------------------------
// Credential sources
// ---------------------------------------------------------------------------

/**
 * The minimum an input has to offer for the credential predicates to read it:
 * a header lookup and a cookie lookup, both case-insensitive on the header
 * side and both allowed to return nothing.
 *
 * Build one with {@link fromHeaders}, {@link fromCookies} or
 * {@link fromRequest} rather than by hand.
 *
 * @since 1.0.0
 * @category models
 */
export interface CredentialSource {
  readonly header: (name: string) => string | null | undefined;
  readonly cookie: (name: string) => string | null | undefined;
}

/** Parse a `Cookie` header into a lookup. Returns `undefined` for absent names. */
const parseCookieHeader = (raw: string | null | undefined): ReadonlyMap<string, string> => {
  const out = new Map<string, string>();
  if (raw === null || raw === undefined || raw === "") return out;
  for (const pair of raw.split(";")) {
    const eq = pair.indexOf("=");
    if (eq === -1) continue;
    const name = pair.slice(0, eq).trim();
    if (name === "") continue;
    // Only the first occurrence wins, matching how servers read cookie jars.
    if (!out.has(name)) out.set(name, pair.slice(eq + 1).trim());
  }
  return out;
};

/**
 * A {@link CredentialSource} over request headers — a Web `Headers`, or a plain
 * record as a Node-style `IncomingMessage.headers` gives you.
 *
 * Cookies are read by parsing the `Cookie` header, so this covers a raw
 * Cloudflare `Request` with nothing else to hand.
 *
 * @since 1.0.0
 * @category constructors
 */
export const fromHeaders = (
  headers: Headers | Record<string, string | ReadonlyArray<string> | undefined>,
): CredentialSource => {
  const get =
    typeof (headers as Headers).get === "function"
      ? (name: string) => (headers as Headers).get(name)
      : (name: string) => {
          const value = (headers as Record<string, string | ReadonlyArray<string> | undefined>)[
            name.toLowerCase()
          ];
          return Array.isArray(value) ? value[0] : (value as string | undefined);
        };
  let cookies: ReadonlyMap<string, string> | undefined;
  return {
    header: get,
    cookie: (name) => {
      cookies ??= parseCookieHeader(get("cookie"));
      return cookies.get(name);
    },
  };
};

/**
 * A {@link CredentialSource} over a cookie jar with a `get(name)` method — the
 * shape SvelteKit's `event.cookies` and most framework jars have.
 *
 * Pass `headers` too when the request may carry a bearer token or API key, so
 * the machine-credential spellings are visible to the predicates as well.
 *
 * @since 1.0.0
 * @category constructors
 */
export const fromCookies = (
  cookies: { readonly get: (name: string) => string | null | undefined },
  headers?: Headers | Record<string, string | ReadonlyArray<string> | undefined>,
): CredentialSource => {
  const fromHeadersSource = headers === undefined ? undefined : fromHeaders(headers);
  return {
    header: (name) => fromHeadersSource?.header(name),
    cookie: (name) => cookies.get(name),
  };
};

/**
 * A {@link CredentialSource} over a Web `Request`.
 *
 * @since 1.0.0
 * @category constructors
 */
export const fromRequest = (request: { readonly headers: Headers }): CredentialSource =>
  fromHeaders(request.headers);

// ---------------------------------------------------------------------------
// Credential presence
// ---------------------------------------------------------------------------

/**
 * Configuration for the credential predicates: cookie naming (shared with the
 * middleware, see `SessionCookies`) plus the header spellings a machine
 * caller uses.
 *
 * @since 1.0.0
 * @category models
 */
export interface CredentialConfig extends SessionCookies.SessionCookieNaming {
  /**
   * Header names carrying a machine API key. Default `["x-api-key"]`.
   *
   * Pass the same value to the credential gate and to whatever reads the key,
   * so "what the gate forwards" and "what the plugin reads" cannot drift.
   */
  readonly apiKeyHeaders?: ReadonlyArray<string>;
}

const DEFAULT_API_KEY_HEADERS: ReadonlyArray<string> = ["x-api-key"];

/**
 * What kind of credential a request carries.
 *
 * @since 1.0.0
 * @category models
 */
export type CredentialKind =
  /** The session cookie. */
  | "session-cookie"
  /** The signed session-data cache cookie. */
  | "session-cache-cookie"
  /** `Authorization: Bearer <token>` or `Authorization: Token <token>`. */
  | "bearer"
  /** A machine API key header. */
  | "api-key";

/**
 * What {@link detectCredential} found.
 *
 * @since 1.0.0
 * @category models
 */
export interface CredentialPresence {
  /** Any credential at all. When `false`, resolution provably cannot succeed. */
  readonly present: boolean;
  /** Every kind found, in the order listed on {@link CredentialKind}. */
  readonly kinds: ReadonlyArray<CredentialKind>;
  /**
   * A browser-borne session credential is present (a session or cache cookie).
   *
   * This is the half of the `Set-Cookie` relay rule that says *who the
   * response is for* — see `Http.RemoteSession`.
   */
  readonly hasSessionCookie: boolean;
  /**
   * A machine credential is present.
   *
   * A relay must not hand `Set-Cookie` to a caller that has one: it would
   * plant session state in whatever cookie jar its HTTP client happens to
   * keep, for no benefit — the key, not a session, is its credential.
   */
  readonly hasApiKey: boolean;
  /** A bearer/token `Authorization` header is present. */
  readonly hasBearer: boolean;
}

const bearerToken = (source: CredentialSource): string | undefined => {
  const auth = source.header("authorization");
  if (auth === null || auth === undefined || auth === "") return undefined;
  const space = auth.indexOf(" ");
  if (space === -1) return undefined;
  const scheme = auth.slice(0, space);
  const value = auth.slice(space + 1).trim();
  // Matches the middleware's own read: `Bearer` and `Token` both carry a
  // session token in effect-auth.
  return (scheme === "Bearer" || scheme === "Token") && value !== "" ? value : undefined;
};

/**
 * Read the API key off a request, using the same header list the gate uses.
 *
 * @since 1.0.0
 * @category accessors
 */
export const extractApiKey = (
  source: CredentialSource,
  config?: CredentialConfig,
): string | undefined => {
  for (const header of config?.apiKeyHeaders ?? DEFAULT_API_KEY_HEADERS) {
    const value = source.header(header);
    if (value !== null && value !== undefined && value !== "") return value;
  }
  return undefined;
};

/**
 * Read the session token off a request — the `Authorization: Bearer/Token`
 * header first, then the session cookie, exactly as the middleware does.
 *
 * @since 1.0.0
 * @category accessors
 */
export const extractSessionToken = (
  source: CredentialSource,
  config?: CredentialConfig,
): string | undefined => {
  const bearer = bearerToken(source);
  if (bearer !== undefined) return bearer;
  const cookie = source.cookie(SessionCookies.cookieNames(config).session);
  return cookie === null || cookie === "" ? undefined : (cookie ?? undefined);
};

/**
 * Classify the credentials a request carries, with no Effect runtime and no
 * restated cookie name.
 *
 * @example The cookieless fast path, at a raw Worker `Request`
 * ```ts
 * import { SessionResolution } from "@thomasfosterau/effect-auth"
 *
 * const credential = SessionResolution.detectCredential(
 *   SessionResolution.fromRequest(request),
 *   { name: "app_session" },
 * )
 * // `credential.present === false` → skip the binding call entirely.
 * ```
 *
 * @since 1.0.0
 * @category accessors
 */
export const detectCredential = (
  source: CredentialSource,
  config?: CredentialConfig,
): CredentialPresence => {
  const names = SessionCookies.cookieNames(config);
  const nonEmpty = (value: string | null | undefined): boolean =>
    value !== null && value !== undefined && value !== "";

  const hasCookie = nonEmpty(source.cookie(names.session));
  const hasCacheCookie = nonEmpty(source.cookie(names.data));
  const hasBearer = bearerToken(source) !== undefined;
  const hasApiKey = extractApiKey(source, config) !== undefined;

  const kinds: Array<CredentialKind> = [];
  if (hasCookie) kinds.push("session-cookie");
  if (hasCacheCookie) kinds.push("session-cache-cookie");
  if (hasBearer) kinds.push("bearer");
  if (hasApiKey) kinds.push("api-key");

  return {
    present: kinds.length > 0,
    kinds,
    hasSessionCookie: hasCookie || hasCacheCookie,
    hasApiKey,
    hasBearer,
  };
};

/**
 * Whether the request carries any credential — the cookieless fast-path
 * predicate, in one call.
 *
 * `false` means resolution provably cannot succeed, so it can be skipped
 * outright. Pass the result (or the richer {@link CredentialPresence}) to
 * {@link resolve} so the skip is reported as `skipped` rather than folded into
 * `anonymous`.
 *
 * @since 1.0.0
 * @category accessors
 */
export const hasSessionCredential = (
  source: CredentialSource,
  config?: CredentialConfig,
): boolean => detectCredential(source, config).present;

// ---------------------------------------------------------------------------
// Resolution
// ---------------------------------------------------------------------------

/**
 * A resolution attempt's result: the session, and what happened getting it.
 *
 * @since 1.0.0
 * @category models
 */
export interface SessionResolutionResult {
  readonly session: Option.Option<Types.SessionWithUser>;
  readonly outcome: AuthOutcome;
}

/** Options shared by {@link resolve} and {@link resolveFailOpen}. */
export interface ResolveOptions<E, R> {
  /**
   * What {@link detectCredential} found, or a plain boolean when the caller
   * decided presence some other way. When there is no credential, `resolve` is
   * never run and the outcome is `skipped`.
   */
  readonly credential: CredentialPresence | boolean;
  /**
   * The actual resolution — a service-binding call, a store read, whatever the
   * edge does. Returns `Option.none()` for "ran, nobody was signed in".
   */
  readonly resolve: Effect.Effect<Option.Option<Types.SessionWithUser>, E, R>;
}

const isPresent = (credential: CredentialPresence | boolean): boolean =>
  typeof credential === "boolean" ? credential : credential.present;

const skipped: SessionResolutionResult = { session: Option.none(), outcome: "skipped" };

const report = (outcome: AuthOutcome): Effect.Effect<void> =>
  Effect.andThen(
    Observability.recordSessionResolution(outcome),
    Effect.annotateCurrentSpan("auth.outcome", outcome),
  );

/**
 * Resolve the session at an app edge, **failing closed**: a fault stays in the
 * error channel and is the caller's to handle.
 *
 * Skips resolution entirely when no credential is present, and reports the
 * outcome (`skipped` / `resolved` / `anonymous`, or `degraded` before
 * re-raising) as a metric and a span attribute.
 *
 * Fail closed is the right direction whenever anonymous is **not** the
 * lower-privilege outcome for your app — see {@link resolveFailOpen} for the
 * precondition that makes the other direction safe.
 *
 * @since 1.0.0
 * @category resolution
 */
export const resolve = <E, R>(
  options: ResolveOptions<E, R>,
): Effect.Effect<SessionResolutionResult, E, R> =>
  Effect.gen(function* () {
    if (!isPresent(options.credential)) {
      yield* report("skipped");
      return skipped;
    }
    const session = yield* options.resolve.pipe(Effect.tapCause(() => report("degraded")));
    const outcome: AuthOutcome = Option.isSome(session) ? "resolved" : "anonymous";
    yield* report(outcome);
    return { session, outcome };
  }).pipe(Effect.withSpan("effect-auth.resolve-session"));

/** Options for {@link resolveFailOpen}. */
export interface ResolveFailOpenOptions<E, R> extends ResolveOptions<E, R> {
  /**
   * Called with the cause whenever resolution faults and the request is
   * degraded to anonymous.
   *
   * Mandatory by design. Fail-open's failure mode is that it is *quiet*: an
   * unreachable session service looks exactly like a site where nobody is
   * signed in, and stays that way until someone notices the sign-in rate. This
   * callback is where that becomes loud — log it, count it, page on it. There
   * is deliberately no overload that omits it.
   */
  readonly onDegraded: (cause: Cause.Cause<E>) => Effect.Effect<void>;
}

/**
 * Resolve the session at an app edge, **failing open**: a fault — including
 * the session service being unreachable — degrades the request to anonymous
 * instead of failing it, and reports `degraded`.
 *
 * ### When this is the right direction
 *
 * Only when anonymous is the **lower-privilege** outcome for your app: reads
 * are public, and every write is separately gated server-side on the resolved
 * viewer. Then a session-service fault costs signed-in users their
 * personalisation and nothing else.
 *
 * It is the **wrong** direction whenever anonymous is privileged — an app with
 * a public-by-default read path it gates *down* for some viewers, or one where
 * a missing session means "internal caller" rather than "nobody". There,
 * degrading to anonymous escalates. Use {@link resolve} and fail closed.
 *
 * The check is worth making explicitly rather than inheriting: with a store
 * behind a database, failing closed turns *any* store fault into a site-wide
 * 500, including on routes that never touch auth. Neither direction is free.
 * See `docs/SECURITY.md`.
 *
 * @example
 * ```ts
 * const { session, outcome } = yield* SessionResolution.resolveFailOpen({
 *   credential,
 *   resolve: remote.resolve(request),
 *   onDegraded: (cause) =>
 *     Effect.logError("session resolution degraded to anonymous", cause),
 * })
 * ```
 *
 * @since 1.0.0
 * @category resolution
 */
export const resolveFailOpen = <E, R>(
  options: ResolveFailOpenOptions<E, R>,
): Effect.Effect<SessionResolutionResult, never, R> =>
  Effect.gen(function* () {
    if (!isPresent(options.credential)) {
      yield* report("skipped");
      return skipped;
    }
    return yield* options.resolve.pipe(
      Effect.flatMap((session) => {
        const outcome: AuthOutcome = Option.isSome(session) ? "resolved" : "anonymous";
        return Effect.as(report(outcome), { session, outcome });
      }),
      // Catches defects as well as failures: an unreachable binding often
      // arrives as a thrown `TypeError`, and degrading only on typed failures
      // would 500 on exactly the fault this exists for.
      Effect.catchCause((cause) =>
        Effect.as(Effect.andThen(report("degraded"), options.onDegraded(cause)), {
          session: Option.none<Types.SessionWithUser>(),
          outcome: "degraded" as const,
        }),
      ),
    );
  }).pipe(Effect.withSpan("effect-auth.resolve-session"));
