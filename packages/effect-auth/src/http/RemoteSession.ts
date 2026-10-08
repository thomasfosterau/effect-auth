/**
 * Auth as a **separate service**: resolving the session over a non-`fetch`
 * transport, and relaying `Set-Cookie` back to the browser.
 *
 * ### The topology
 *
 * `Http.make` is mounted in its own internal service — a Cloudflare Worker
 * reached only over a service binding, a private container, an in-process
 * handler under test. The app's own front door resolves the session over that
 * transport on every request, and forwards credential mutation to it.
 *
 * Two things that topology needs, which a typed client alone cannot give:
 *
 * 1. **A transport that is not `globalThis.fetch`.** {@link layerFetcher} turns
 *    any fetch-alike — a service binding, a mounted `Http.make` handler, a test
 *    double — into an `HttpClient`, so `Http.client(baseUrl)` works unchanged
 *    over it.
 * 2. **A channel for `Set-Cookie`.** Establishing or clearing a session means
 *    getting that header to the browser, and it has no representation in a
 *    typed JSON success value. A client's `relay` (see {@link make}) forwards
 *    the request and relays the raw response — status, body and `Set-Cookie`
 *    intact.
 *
 * ### Header policy is the library's, not the app's
 *
 * Forwarding the inbound request's headers wholesale is how you get a 415 on a
 * bodyless `GET`: a forwarded `content-length` makes a router believe the
 * request has a body, at which point its content-type allow-list runs against
 * whatever the app's own dispatch uses (`application/vnd.api+json`, say) and
 * rejects it. The session then fails to resolve, the request degrades to
 * anonymous, and every gated route answers 401.
 *
 * {@link forwardedHeaders} is an **allow-list** for exactly this reason:
 * `content-type` and `content-length` are not on it, so the failure is not
 * reachable by forgetting to strip them. See {@link HeaderPolicy} to extend it.
 *
 * ### `Set-Cookie` on session *reads* matters too
 *
 * When the signed session-data cookie cache is on, a session read refreshes it
 * with a `Set-Cookie` on the response. An app that resolves the session over a
 * binding and drops that header gets a cache that stops refreshing after its
 * first window, silently. {@link RemoteSessionResult} therefore carries the
 * `Set-Cookie` lines to replay onto the outgoing response.
 *
 * ### Never relay a cookie to a machine caller
 *
 * A request bearing an API key is not a browser. Handing it a `Set-Cookie`
 * plants session state in whatever cookie jar its HTTP client happens to keep,
 * for no benefit — the key, not a session, is its credential. The relay drops
 * `Set-Cookie` whenever the *inbound* request carries a machine credential,
 * including the mixed case where it carries both a cookie and a key.
 *
 * @module remote-session
 */
import { Data, Effect, Layer, Option, Schema } from "effect";
import { FetchHttpClient, HttpClient } from "effect/http";
import { spanNames } from "../Observability.ts";
import * as SessionResolution from "../SessionResolution.ts";
import type * as Types from "../Types.ts";
import * as S from "./HttpApiSchema.ts";

// ---------------------------------------------------------------------------
// Transport
// ---------------------------------------------------------------------------

/**
 * Anything that answers a request like `fetch` does.
 *
 * A Cloudflare service binding (`env.AUTH`), a `Http.make` web handler mounted
 * in-process, or a test double all satisfy this.
 *
 * @since 1.0.0
 * @category models
 */
export interface Fetcher {
  readonly fetch: (request: Request) => Promise<Response>;
}

/** A bare fetch function, or an object carrying one. */
export type FetcherLike = Fetcher | ((request: Request) => Promise<Response>);

const asFetch =
  (fetcher: FetcherLike) =>
  (request: Request): Promise<Response> =>
    typeof fetcher === "function" ? fetcher(request) : fetcher.fetch(request);

/**
 * An `HttpClient` layer backed by an arbitrary fetch-alike instead of
 * `globalThis.fetch`.
 *
 * This is the supported way to point the typed client at a service binding:
 * `Http.client(baseUrl)` needs an `HttpClient` in context and does not care
 * where the bytes go.
 *
 * @example Talking to an internal auth Worker with the typed client
 * ```ts
 * import assert from "node:assert/strict"
 * import { Effect } from "effect"
 * import { Http } from "@thomasfosterau/effect-auth"
 *
 * // A stand-in for the auth worker behind the service binding (`env.AUTH` on
 * // Cloudflare), answering in-process: sign-in succeeds for any credentials.
 * const authWorker = async (request: Request): Promise<Response> => {
 *   const { pathname } = new URL(request.url)
 *   if (request.method === "POST" && pathname.endsWith("/sign-in")) {
 *     const user = {
 *       id: "u-1",
 *       email: "user@example.com",
 *       emailVerified: true,
 *       createdAt: 1_700_000_000_000,
 *       updatedAt: 1_700_000_000_000,
 *       attributes: {},
 *     }
 *     return Response.json({ user, needsEmailVerification: false })
 *   }
 *   return new Response(null, { status: 404 })
 * }
 * const env = { AUTH: authWorker }
 * const payload = { email: "user@example.com", password: "password-123" }
 *
 * const program = Effect.gen(function* () {
 *   const client = yield* Http.client("https://auth.internal")
 *   return yield* client.auth.signIn({ payload })
 * }).pipe(Effect.provide(Http.RemoteSession.layerFetcher(env.AUTH)))
 *
 * const result = await Effect.runPromise(program)
 * assert.equal(result.user.id, "u-1")
 * ```
 *
 * @since 1.0.0
 * @category layers
 */
export const layerFetcher = (fetcher: FetcherLike): Layer.Layer<HttpClient.HttpClient> => {
  const send = asFetch(fetcher);
  const asWebRequest = (...[input, init]: Parameters<typeof globalThis.fetch>): Request =>
    input instanceof Request && init === undefined ? input : new Request(input, init);
  return Layer.provide(
    FetchHttpClient.layer,
    Layer.succeed(FetchHttpClient.Fetch, (input, init) => send(asWebRequest(input, init))),
  );
};

// ---------------------------------------------------------------------------
// Header policy
// ---------------------------------------------------------------------------

/**
 * Which inbound headers ride along to the auth service.
 *
 * @since 1.0.0
 * @category models
 */
export interface HeaderPolicy {
  /**
   * Replaces the default allow-list outright. Prefer {@link HeaderPolicy.also}
   * unless you mean to drop one of the defaults.
   */
  readonly forward?: ReadonlyArray<string>;
  /** Additional header names to forward, on top of the defaults. */
  readonly also?: ReadonlyArray<string>;
  /** Header names to add or override on the outgoing request. */
  readonly set?: Readonly<Record<string, string>>;
}

/**
 * The headers forwarded by default.
 *
 * `content-type` and `content-length` are deliberately absent: forwarding them
 * onto a bodyless request is what produces the 415-then-401 failure described
 * at the top of this module. The relay re-adds them from the *body it is
 * actually sending*, never from the inbound request.
 *
 * @since 1.0.0
 * @category constructors
 */
export const defaultForwardedHeaders: ReadonlyArray<string> = [
  // The credential itself.
  "cookie",
  "authorization",
  "x-api-key",
  // Who and where the caller is — rate limiting, trusted-proxy IP resolution,
  // localised mail.
  "cf-connecting-ip",
  "x-forwarded-for",
  "accept-language",
  "user-agent",
  // The CSRF origin check runs on the auth service, so it has to see what the
  // browser actually sent.
  "origin",
  "referer",
];

/**
 * Build the outgoing header set for a call to the auth service.
 *
 * @since 1.0.0
 * @category constructors
 */
export const forwardedHeaders = (inbound: Request | Headers, policy?: HeaderPolicy): Headers => {
  const source = inbound instanceof Headers ? inbound : inbound.headers;
  const out = new Headers();
  const names = policy?.forward ?? defaultForwardedHeaders;
  for (const name of [...names, ...(policy?.also ?? [])]) {
    const value = source.get(name);
    if (value !== null) out.set(name, value);
  }
  for (const [name, value] of Object.entries(policy?.set ?? {})) out.set(name, value);
  return out;
};

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

/**
 * The auth service answered, but not in a way the session read understands —
 * an unexpected status, or a body that does not decode.
 *
 * Transport faults (an unreachable binding) arrive as defects rather than this
 * error, which is why `SessionResolution.resolveFailOpen` degrades on the whole
 * cause rather than only on typed failures.
 *
 * @since 1.0.0
 * @category errors
 */
export class RemoteSessionError extends Data.TaggedError("RemoteSessionError")<{
  readonly message: string;
  readonly status?: number;
  readonly cause?: unknown;
}> {}

// ---------------------------------------------------------------------------
// Session reads
// ---------------------------------------------------------------------------

/**
 * A remote session read: the session if one resolved, and the `Set-Cookie`
 * lines the auth service asked to be set.
 *
 * Replay `setCookie` onto your outgoing response. When the signed cookie cache
 * is enabled this is how it keeps refreshing; drop it and the cache stops
 * refreshing after its first window.
 *
 * @since 1.0.0
 * @category models
 */
export interface RemoteSessionResult {
  readonly session: Option.Option<Types.SessionWithUser>;
  readonly setCookie: ReadonlyArray<string>;
}

const emptyResult: RemoteSessionResult = { session: Option.none(), setCookie: [] };

const decodeView = Schema.decodeUnknownEffect(S.SessionWithUserView);

/**
 * Rebuild the domain record from the wire view: epoch millis back to `Date`s.
 *
 * `UserView` also carries derived `email`/`emailVerified`, which are not
 * `Types.User` fields (login handles are `Identifier` records). They are
 * dropped here rather than folded into `attributes`, so a round trip cannot
 * silently invent an attribute the store never held.
 *
 * @since 1.0.0
 * @category conversions
 */
export const fromSessionWithUserView = (view: S.SessionWithUserView): Types.SessionWithUser => ({
  session: {
    id: view.session.id,
    userId: view.session.userId,
    expiresAt: new Date(view.session.expiresAt),
    createdAt: new Date(view.session.createdAt),
    lastActivityAt: new Date(view.session.lastActivityAt),
    attributes: view.session.attributes,
  },
  user: {
    id: view.user.id,
    ...(view.user.name !== undefined && { name: view.user.name }),
    ...(view.user.image !== undefined && { image: view.user.image }),
    createdAt: new Date(view.user.createdAt),
    updatedAt: new Date(view.user.updatedAt),
    attributes: view.user.attributes,
  },
});

/**
 * Configuration for {@link make}.
 *
 * @since 1.0.0
 * @category models
 */
export interface RemoteSessionOptions {
  /** The transport: a service binding, a mounted handler, a test double. */
  readonly fetcher: FetcherLike;
  /**
   * Base URL of the auth service. Its host is never resolved over DNS when the
   * transport is a binding, but a service binding still requires a
   * well-formed absolute URL. Default `https://auth.internal`.
   */
  readonly baseUrl?: string;
  /** Mount prefix of the auth API on that service. Default `/api/auth`. */
  readonly prefix?: string;
  /** Header forward policy. See {@link defaultForwardedHeaders}. */
  readonly headers?: HeaderPolicy;
  /** Cookie naming and API-key spellings, shared with the credential predicates. */
  readonly credentials?: SessionResolution.CredentialConfig;
}

/**
 * A client for the session seam of a remote auth service.
 *
 * @since 1.0.0
 * @category models
 */
export interface RemoteSessionClient {
  /**
   * What credentials the inbound request carries, using this client's cookie
   * configuration. Feed it to {@link resolveAtEdge} — or read
   * `credential.present` yourself for the cookieless fast path.
   */
  readonly credential: (request: Request) => SessionResolution.CredentialPresence;
  /**
   * Read the session over the transport. Always makes the call; use
   * {@link resolveAtEdge} to get the skip, the fault posture and the outcome.
   */
  readonly read: (request: Request) => Effect.Effect<RemoteSessionResult, RemoteSessionError>;
  /**
   * Forward a request to the auth service and return its response verbatim —
   * status, body and `Set-Cookie` — subject to the machine-caller rule.
   */
  readonly relay: (request: Request, path?: string) => Effect.Effect<Response>;
}

/**
 * Build a {@link RemoteSessionClient}.
 *
 * @example
 * ```ts
 * import assert from "node:assert/strict"
 * import { Effect, Option } from "effect"
 * import { Http } from "@thomasfosterau/effect-auth"
 *
 * // A stand-in for the auth worker behind the service binding (`env.AUTH` on
 * // Cloudflare): it answers the session read for any request carrying a cookie.
 * const authWorker = async (request: Request): Promise<Response> => {
 *   const { pathname } = new URL(request.url)
 *   if (request.method === "GET" && pathname.endsWith("/session")) {
 *     if (request.headers.get("cookie") === null) return new Response(null, { status: 401 })
 *     const user = {
 *       id: "u-1",
 *       email: "user@example.com",
 *       emailVerified: true,
 *       createdAt: 1_700_000_000_000,
 *       updatedAt: 1_700_000_000_000,
 *       attributes: {},
 *     }
 *     const session = {
 *       id: "session-1",
 *       userId: "u-1",
 *       expiresAt: 4_102_444_800_000,
 *       createdAt: 1_700_000_000_000,
 *       lastActivityAt: 1_700_000_000_000,
 *       attributes: {},
 *     }
 *     return Response.json({ session, user })
 *   }
 *   return new Response(null, { status: 404 })
 * }
 * const env = { AUTH: authWorker }
 *
 * const auth = Http.RemoteSession.make({ fetcher: env.AUTH })
 *
 * // The same client answers a signed-in read and a cookieless one.
 * const signedIn = new Request("https://app.example.com/", {
 *   headers: { cookie: "conduit_session=session-token" },
 * })
 * const result = await Effect.runPromise(auth.read(signedIn))
 * assert.ok(Option.isSome(result.session))
 * assert.equal(result.session.value.user.id, "u-1")
 * ```
 *
 * @since 1.0.0
 * @category constructors
 */
export const make = (options: RemoteSessionOptions): RemoteSessionClient => {
  const send = asFetch(options.fetcher);
  const baseUrl = options.baseUrl ?? "https://auth.internal";
  const prefix = options.prefix ?? "/api/auth";
  const url = (path: string) => new URL(`${prefix}${path}`, baseUrl).toString();

  const credential = (request: Request): SessionResolution.CredentialPresence =>
    SessionResolution.detectCredential(SessionResolution.fromRequest(request), options.credentials);

  const read = (request: Request): Effect.Effect<RemoteSessionResult, RemoteSessionError> =>
    Effect.gen(function* () {
      const outbound = new Request(url("/session"), {
        method: "GET",
        headers: forwardedHeaders(request, options.headers),
      });

      const response = yield* Effect.promise(() => send(outbound));
      const setCookie = response.headers.getSetCookie();

      // 401 is "ran, nobody was signed in" — an expected answer, not a fault.
      // Its Set-Cookie still matters: it is how a stale cache cookie is cleared.
      if (response.status === 401) return { session: Option.none(), setCookie };

      if (response.status !== 200) {
        return yield* new RemoteSessionError({
          message: `Session read returned ${response.status}`,
          status: response.status,
        });
      }

      const body = yield* Effect.tryPromise({
        try: () => response.json() as Promise<unknown>,
        catch: (cause) =>
          new RemoteSessionError({ message: "Session read body was not JSON", cause }),
      });

      const view = yield* decodeView(body).pipe(
        Effect.mapError(
          (cause) => new RemoteSessionError({ message: "Session read body did not decode", cause }),
        ),
      );

      return { session: Option.some(fromSessionWithUserView(view)), setCookie };
    }).pipe(Effect.withSpan(spanNames.remoteSessionRead));

  const relay = (request: Request, path?: string): Effect.Effect<Response> =>
    Effect.gen(function* () {
      const target = path === undefined ? new URL(request.url).pathname : `${prefix}${path}`;
      const headers = forwardedHeaders(request, options.headers);
      const hasBody = request.method !== "GET" && request.method !== "HEAD";

      // Content headers come from the body being sent, never from the inbound
      // request — see the 415 note at the top of this module.
      const contentType = hasBody ? request.headers.get("content-type") : null;
      if (contentType !== null) headers.set("content-type", contentType);

      const body = hasBody ? yield* Effect.promise(() => request.arrayBuffer()) : undefined;

      const response = yield* Effect.promise(() =>
        send(
          new Request(new URL(target, baseUrl).toString(), {
            method: request.method,
            headers,
            ...(body === undefined ? {} : { body }),
          }),
        ),
      );

      return relayResponse(response, credential(request));
    }).pipe(Effect.withSpan(spanNames.remoteSessionRelay));

  return { credential, read, relay };
};

/**
 * Rebuild an upstream response for the browser, applying the machine-caller
 * rule: `Set-Cookie` is relayed only when the inbound request carried a browser
 * session cookie and no machine credential.
 *
 * Exported so an app relaying through its own code path gets the same rule.
 *
 * @since 1.0.0
 * @category constructors
 */
export const relayResponse = (
  upstream: Response,
  inbound: SessionResolution.CredentialPresence,
): Response => {
  const cookies = upstream.headers.getSetCookie();
  if (cookies.length === 0) return upstream;

  // A key-bearing caller is not a browser. The mixed case — a request carrying
  // both a cookie and a key — is excluded too: the key is its credential, so
  // the session state has nowhere useful to go.
  const mayReceiveCookies = inbound.hasSessionCookie && !inbound.hasApiKey;
  if (mayReceiveCookies) return upstream;

  const headers = new Headers(upstream.headers);
  headers.delete("set-cookie");
  return new Response(upstream.body, {
    status: upstream.status,
    statusText: upstream.statusText,
    headers,
  });
};

// ---------------------------------------------------------------------------
// The edge, end to end
// ---------------------------------------------------------------------------

/**
 * What a full edge resolution produced: the session, the cookies to replay,
 * and the one {@link SessionResolution.AuthOutcome} describing what happened.
 *
 * @since 1.0.0
 * @category models
 */
export interface EdgeSession extends RemoteSessionResult {
  readonly outcome: SessionResolution.AuthOutcome;
  /**
   * How this caller got in, derived from the credential it presented. Pass it
   * straight to `SessionContext.authenticatedLayer(session, { credentialClass })`
   * so the policy kernel sees the same credential class the HTTP middleware
   * would have provided.
   */
  readonly credentialClass: SessionResolution.CredentialClass;
}

/** Options for {@link resolveAtEdge} and {@link resolveAtEdgeFailOpen}. */
export interface ResolveAtEdgeOptions {
  readonly client: RemoteSessionClient;
  readonly request: Request;
}

const toEdge =
  (credential: SessionResolution.CredentialPresence) =>
  (result: {
    readonly value: RemoteSessionResult;
    readonly outcome: SessionResolution.AuthOutcome;
  }): EdgeSession => ({
    ...result.value,
    outcome: result.outcome,
    credentialClass: SessionResolution.credentialClassOf(credential),
  });

/**
 * Resolve the session over the transport at an app edge, **failing closed**.
 *
 * Skips the call entirely for a cookieless request, reports the outcome, and
 * carries the `Set-Cookie` lines to replay.
 *
 * @since 1.0.0
 * @category resolution
 */
export const resolveAtEdge = (
  options: ResolveAtEdgeOptions,
): Effect.Effect<EdgeSession, RemoteSessionError> => {
  const credential = options.client.credential(options.request);
  return Effect.map(
    SessionResolution.resolveWith({
      credential,
      resolve: options.client.read(options.request),
      session: (result) => result.session,
      empty: emptyResult,
    }),
    toEdge(credential),
  );
};

/**
 * Resolve the session over the transport at an app edge, **failing open**: an
 * unreachable auth service degrades the request to anonymous rather than
 * failing it.
 *
 * This is the posture the split-service topology usually wants — a session read
 * sits on the hot path of *every* request, so a fault would otherwise 500 the
 * whole site, including routes that never touch auth. It is only safe when
 * anonymous is the lower-privilege outcome; `docs/ARCHITECTURE.md` states the
 * precondition, and `onDegraded` is mandatory so the degrade is never silent.
 *
 * @example A Worker front door
 * ```ts
 * import assert from "node:assert/strict"
 * import { Effect, Option } from "effect"
 * import { Http, SessionCookies } from "@thomasfosterau/effect-auth"
 *
 * // A stand-in for the auth worker behind the service binding: it answers the
 * // session read for any request carrying a cookie.
 * const authWorker = async (request: Request): Promise<Response> => {
 *   const { pathname } = new URL(request.url)
 *   if (request.method === "GET" && pathname.endsWith("/session")) {
 *     if (request.headers.get("cookie") === null) return new Response(null, { status: 401 })
 *     const user = {
 *       id: "u-1",
 *       email: "user@example.com",
 *       emailVerified: true,
 *       createdAt: 1_700_000_000_000,
 *       updatedAt: 1_700_000_000_000,
 *       attributes: {},
 *     }
 *     const session = {
 *       id: "session-1",
 *       userId: "u-1",
 *       expiresAt: 4_102_444_800_000,
 *       createdAt: 1_700_000_000_000,
 *       lastActivityAt: 1_700_000_000_000,
 *       attributes: {},
 *     }
 *     return Response.json({ session, user })
 *   }
 *   return new Response(null, { status: 404 })
 * }
 *
 * // The remote-session client from `RemoteSession.make`, and the incoming request.
 * const auth = Http.RemoteSession.make({ fetcher: authWorker })
 * const names = SessionCookies.cookieNames()
 * const request = new Request("https://app.example.com/dashboard", {
 *   headers: { cookie: `${names.session}=session-token` },
 * })
 *
 * const handle = Effect.gen(function* () {
 *   const { session, outcome, setCookie } = yield* Http.RemoteSession.resolveAtEdgeFailOpen({
 *     client: auth,
 *     request,
 *     onDegraded: (cause) => Effect.logError("auth binding unreachable", cause),
 *   })
 *   // `session` feeds `SessionContext.layer`; `setCookie` is replayed on the response.
 *   return { session, outcome, setCookie }
 * })
 *
 * const edge = await Effect.runPromise(handle)
 * assert.ok(Option.isSome(edge.session))
 * assert.equal(edge.session.value.user.id, "u-1")
 * assert.deepEqual(edge.setCookie, [])
 * ```
 *
 * @since 1.0.0
 * @category resolution
 */
export const resolveAtEdgeFailOpen = (
  options: ResolveAtEdgeOptions & {
    readonly onDegraded: SessionResolution.ResolveWithFailOpenOptions<
      RemoteSessionResult,
      RemoteSessionError,
      never
    >["onDegraded"];
  },
): Effect.Effect<EdgeSession> => {
  const credential = options.client.credential(options.request);
  return Effect.map(
    SessionResolution.resolveWithFailOpen({
      credential,
      resolve: options.client.read(options.request),
      session: (result) => result.session,
      empty: emptyResult,
      onDegraded: options.onDegraded,
    }),
    toEdge(credential),
  );
};

/**
 * Replay relayed `Set-Cookie` lines onto an outgoing response.
 *
 * @since 1.0.0
 * @category constructors
 */
export const withSetCookie = (response: Response, setCookie: ReadonlyArray<string>): Response => {
  if (setCookie.length === 0) return response;
  const headers = new Headers(response.headers);
  for (const cookie of setCookie) headers.append("set-cookie", cookie);
  return new Response(response.body, {
    status: response.status,
    statusText: response.statusText,
    headers,
  });
};
