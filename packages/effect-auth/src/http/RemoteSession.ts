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
 * A request bearing an API key or a bearer token is not a browser. Handing it
 * a `Set-Cookie` plants session state in whatever cookie jar its HTTP client
 * happens to keep, for no benefit — the key or token, not a session, is its
 * credential. The relay drops `Set-Cookie` whenever the *inbound* request
 * carries a machine credential, including the mixed case where it carries both
 * a cookie and a key or token. Every other caller receives it, a browser with
 * no cookie yet included, so a first sign-in through the relay signs in (#619).
 *
 * ### A key resolves to its user, not to a session
 *
 * {@link resolveAtEdge} sends a key-bearing request to `GET /api-keys/current`
 * (#730) and answers `{ session: None, user, apiKey, credentialClass:
 * "machine" }`; the key wins over any cookie the request also carries, which is
 * not forwarded on that call. An auth service without an `ApiKeyService`
 * answers `404`, which fails the resolution closed rather than reading the
 * cookie. Each resolution consumes one use of the key (`remaining`
 * decrements, `lastUsedAt` moves); a non-consuming check is #645.
 *
 * @module remote-session
 */
import { Data, Effect, Layer } from "effect";
import * as Arr from "effect/Array";
import * as Option from "effect/Option";
import * as P from "effect/Predicate";
import * as R from "effect/Record";
import * as Schema from "effect/Schema";
import { FetchHttpClient, HttpClient } from "effect/http";
import type { ApiKey } from "../ApiKey.ts";
import { spanNames } from "../Observability.ts";
import * as SessionResolution from "../SessionResolution.ts";
import type * as Types from "../Types.ts";
import { MEDIA_TYPE } from "@thomasfosterau/effect-jsonapi/schema";
import { noStoreWithSetCookie } from "./CacheControl.ts";
import { CurrentApiKeyDocument, SessionDocument } from "./HttpApi.ts";
import * as S from "./HttpApiSchema.ts";
import type * as Resources from "./Resources.ts";

// ---------------------------------------------------------------------------
// Transport
// ---------------------------------------------------------------------------

/**
 * Anything that answers a request like `fetch` does.
 *
 * A Cloudflare service binding (`env.AUTH`), a `Http.make` web handler mounted
 * in-process, or a test double all satisfy this.
 *
 * @since 0.1.0
 * @category models
 */
export interface Fetcher {
  readonly fetch: (request: Request) => Promise<Response>;
}

/** A bare fetch function, or an object carrying one. */
export type FetcherLike = Fetcher | ((request: Request) => Promise<Response>);

/** A promise that rejected; {@link promiseOrDie} dies with its `cause`. */
class PromiseRejection extends Data.TaggedError("PromiseRejection")<{
  readonly cause: unknown;
}> {}

/**
 * Run a promise whose rejection is a defect, as `Effect.promise` does: the
 * defect is the rejection value itself.
 */
const promiseOrDie = <A>(evaluate: () => Promise<A>): Effect.Effect<A> =>
  Effect.tryPromise({ try: evaluate, catch: (cause) => new PromiseRejection({ cause }) }).pipe(
    Effect.catchTag("PromiseRejection", (rejection) => Effect.die(rejection.cause)),
  );

const asFetch =
  (fetcher: FetcherLike) =>
  (request: Request): Promise<Response> =>
    P.isFunction(fetcher) ? fetcher(request) : fetcher.fetch(request);

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
 * import * as Http from "@thomasfosterau/effect-auth/http"
 *
 * // A stand-in for the auth worker behind the service binding (`env.AUTH` on
 * // Cloudflare), answering in-process: sign-in succeeds for any credentials.
 * const authWorker = async (request: Request): Promise<Response> => {
 *   const { pathname } = new URL(request.url)
 *   if (request.method === "POST" && pathname.endsWith("/sessions")) {
 *     const at = 1_700_000_000_000
 *     const document = {
 *       data: {
 *         type: "sessions",
 *         id: "s-1",
 *         attributes: { expiresAt: at + 3_600_000, createdAt: at, lastActivityAt: at, attributes: {} },
 *         relationships: { user: { data: { type: "users", id: "u-1" } } },
 *       },
 *       included: [
 *         {
 *           type: "users",
 *           id: "u-1",
 *           attributes: { email: "user@example.com", emailVerified: true, createdAt: at, updatedAt: at, attributes: {} },
 *         },
 *       ],
 *       meta: { needsEmailVerification: false },
 *     }
 *     return new Response(JSON.stringify(document), {
 *       status: 201,
 *       headers: { "content-type": "application/vnd.api+json" },
 *     })
 *   }
 *   return new Response(null, { status: 404 })
 * }
 * const env = { AUTH: authWorker }
 * // Sign in: `POST /sessions` with a password credential.
 * const payload = {
 *   data: {
 *     type: "sessions",
 *     attributes: {
 *       credential: { method: "password", email: "user@example.com", password: "password-123" },
 *     },
 *   },
 * } as const
 *
 * const program = Effect.gen(function* () {
 *   const client = yield* Http.client("https://auth.internal")
 *   return yield* client.sessions.create({ payload })
 * }).pipe(Effect.provide(Http.RemoteSession.layerFetcher(env.AUTH)))
 *
 * const result = await Effect.runPromise(program)
 * // A `201` carries the session, its user included; a `202` carries neither.
 * assert("included" in result)
 * assert.equal(result.included?.[0]?.id, "u-1")
 * ```
 *
 * @since 0.1.0
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
 * @since 0.1.0
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
 * @since 0.1.0
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
 * @since 0.1.0
 * @category constructors
 */
export const forwardedHeaders = (inbound: Request | Headers, policy?: HeaderPolicy): Headers => {
  const source = inbound instanceof Headers ? inbound : inbound.headers;
  const out = new Headers();
  const names = policy?.forward ?? defaultForwardedHeaders;
  [...names, ...(policy?.also ?? [])].forEach((name) => {
    const value = source.get(name);
    if (value !== null) out.set(name, value);
  });
  R.toEntries(policy?.set ?? {}).forEach(([name, value]) => out.set(name, value));
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
 * @since 0.1.0
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
 * @since 0.1.0
 * @category models
 */
export interface RemoteSessionResult {
  readonly session: Option.Option<Types.SessionWithUser>;
  readonly setCookie: ReadonlyArray<string>;
  /**
   * On the API-key path ({@link RemoteSessionClient.readApiKey}, #730): the
   * user the presented key acts as. `session` is `None` there, since a key is
   * not a session. Absent on a session read.
   */
  readonly user?: Types.User | undefined;
  /** On the API-key path: the key that resolved, its public fields only. */
  readonly apiKey?: RemoteApiKey | undefined;
}

/**
 * An API key as `GET /api-keys/current` describes it: `ApiKey.ApiKey` without
 * the key's hash and its refill bookkeeping, which never leave the auth
 * service (and never the plaintext key, which nothing stores).
 *
 * @since 0.4.0
 * @category models
 */
export type RemoteApiKey = Omit<
  ApiKey,
  "keyHash" | "refillAmount" | "refillInterval" | "refillMax" | "lastRefillAt"
>;

const emptyResult: RemoteSessionResult = { session: Option.none(), setCookie: [] };

const decodeDocument = Schema.decodeUnknownEffect(SessionDocument);

const decodeApiKeyDocument = Schema.decodeUnknownEffect(
  Schema.fromJsonString(CurrentApiKeyDocument),
);

/**
 * The key and its user from the `GET /api-keys/current` document, or `None`
 * when the document leaves the user out. As with {@link fromSessionDocument},
 * the user's derived `email` fields are dropped.
 *
 * @since 0.4.0
 * @category conversions
 */
export const fromApiKeyDocument = (
  document: typeof CurrentApiKeyDocument.Type,
): Option.Option<{ readonly apiKey: RemoteApiKey; readonly user: Types.User }> => {
  const key = document.data;
  const userId = key.relationships?.user.data.id;
  const a = key.attributes;
  return Option.map(
    Arr.findFirst(document.included ?? [], (resource) => resource.id === userId),
    (user) => ({
      apiKey: {
        id: key.id,
        userId: user.id,
        ...(a.name !== undefined && { name: a.name }),
        ...(a.prefix !== undefined && { prefix: a.prefix }),
        start: a.start,
        enabled: a.enabled,
        ...(a.expiresAt !== undefined && { expiresAt: a.expiresAt }),
        ...(a.lastUsedAt !== undefined && { lastUsedAt: a.lastUsedAt }),
        ...(a.permissions !== undefined && { permissions: a.permissions }),
        metadata: a.metadata,
        ...(a.remaining !== undefined && { remaining: a.remaining }),
        ...(a.rateLimit !== undefined && { rateLimit: a.rateLimit }),
        createdAt: a.createdAt,
        updatedAt: a.updatedAt,
      },
      user: fromUserResource(user),
    }),
  );
};

/**
 * The domain user of an included `users` resource; its derived `email` fields
 * are not `Types.User` fields and are dropped.
 */
const fromUserResource = (user: Resources.User): Types.User => ({
  id: user.id,
  ...(user.attributes.name !== undefined && { name: user.attributes.name }),
  ...(user.attributes.image !== undefined && { image: user.attributes.image }),
  createdAt: user.attributes.createdAt,
  updatedAt: user.attributes.updatedAt,
  attributes: user.attributes.attributes,
});

/**
 * The domain record from the `GET /sessions/current?include=user` document:
 * the `sessions` primary data and the `users` resource it names in
 * `included`, or `None` when the document leaves the user out.
 *
 * As with {@link fromSessionWithUserView}, the user's derived `email` fields
 * are not `Types.User` fields and are dropped.
 *
 * @since 0.1.0
 * @category conversions
 */
export const fromSessionDocument = (
  document: typeof SessionDocument.Type,
): Option.Option<Types.SessionWithUser> => {
  const session = document.data;
  const userId = session.relationships?.user.data.id;
  return Option.map(
    Arr.findFirst(document.included ?? [], (resource) => resource.id === userId),
    (user): Types.SessionWithUser => ({
      session: {
        id: session.id,
        userId: user.id,
        expiresAt: session.attributes.expiresAt,
        createdAt: session.attributes.createdAt,
        lastActivityAt: session.attributes.lastActivityAt,
        attributes: session.attributes.attributes,
      },
      user: fromUserResource(user),
    }),
  );
};

const decodeMillis = Schema.decodeUnknownEffect(Schema.DateFromMillis);

/**
 * Rebuild the domain record from the wire view: epoch millis back to `Date`s.
 *
 * The instants come from a remote server, so each is decoded with
 * `Schema.DateFromMillis`: a value that is not a valid `Date` fails with a
 * `SchemaError` instead of becoming an Invalid Date.
 *
 * `UserView` also carries derived `email`/`emailVerified`, which are not
 * `Types.User` fields (login handles are `Identifier` records). They are
 * dropped here rather than folded into `attributes`, so a round trip cannot
 * silently invent an attribute the store never held.
 *
 * @since 0.1.0
 * @category conversions
 */
export const fromSessionWithUserView = (
  view: S.SessionWithUserView,
): Effect.Effect<Types.SessionWithUser, Schema.SchemaError> =>
  Effect.all(
    {
      expiresAt: decodeMillis(view.session.expiresAt),
      sessionCreatedAt: decodeMillis(view.session.createdAt),
      lastActivityAt: decodeMillis(view.session.lastActivityAt),
      userCreatedAt: decodeMillis(view.user.createdAt),
      updatedAt: decodeMillis(view.user.updatedAt),
    },
    { concurrency: 1 },
  ).pipe(
    Effect.map((at) => ({
      session: {
        id: view.session.id,
        userId: view.session.userId,
        expiresAt: at.expiresAt,
        createdAt: at.sessionCreatedAt,
        lastActivityAt: at.lastActivityAt,
        attributes: view.session.attributes,
      },
      user: {
        id: view.user.id,
        ...(view.user.name !== undefined && { name: view.user.name }),
        ...(view.user.image !== undefined && { image: view.user.image }),
        createdAt: at.userCreatedAt,
        updatedAt: at.updatedAt,
        attributes: view.user.attributes,
      },
    })),
  );

/**
 * Configuration for {@link make}.
 *
 * @since 0.1.0
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
 * @since 0.1.0
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
   * Resolve the API key the inbound request carries over the transport
   * (`GET /api-keys/current`, #730): `{ session: None, user, apiKey }` for a
   * key that resolves, `{ session: None }` with no `user` for the auth
   * service's `401` (an unknown, disabled, expired or exhausted key). Any
   * other answer (`404` when the auth service mounts no `ApiKeyService`,
   * `429` for a key over its own limit, a `5xx`) is a
   * {@link RemoteSessionError}. Only the API-key headers ride along, never the
   * cookie, so the key cannot fall back to a session.
   *
   * Each call consumes one use of the key: `remaining` decrements and
   * `lastUsedAt` moves (a non-consuming check is #645).
   *
   * Optional only so a hand-built client keeps compiling; {@link make}
   * always provides it, and {@link resolveAtEdge} fails closed without it.
   */
  readonly readApiKey?:
    | ((request: Request) => Effect.Effect<RemoteSessionResult, RemoteSessionError>)
    | undefined;
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
 * import { Effect } from "effect"
 * import * as Option from "effect/Option"
 * import * as Http from "@thomasfosterau/effect-auth/http"
 *
 * // A stand-in for the auth worker behind the service binding (`env.AUTH` on
 * // Cloudflare): it answers the session read for any request carrying a cookie.
 * const authWorker = async (request: Request): Promise<Response> => {
 *   const { pathname } = new URL(request.url)
 *   if (request.method === "GET" && pathname.endsWith("/sessions/current")) {
 *     if (request.headers.get("cookie") === null) return new Response(null, { status: 401 })
 *     // `GET /sessions/current?include=user`: the session, its user included.
 *     const document = {
 *       data: {
 *         type: "sessions",
 *         id: "session-1",
 *         attributes: {
 *           expiresAt: 4_102_444_800_000,
 *           createdAt: 1_700_000_000_000,
 *           lastActivityAt: 1_700_000_000_000,
 *           attributes: {},
 *         },
 *         relationships: { user: { data: { type: "users", id: "u-1" } } },
 *       },
 *       included: [
 *         {
 *           type: "users",
 *           id: "u-1",
 *           attributes: {
 *             email: "user@example.com",
 *             emailVerified: true,
 *             createdAt: 1_700_000_000_000,
 *             updatedAt: 1_700_000_000_000,
 *             attributes: {},
 *           },
 *         },
 *       ],
 *     }
 *     return Response.json(document, { headers: { "content-type": "application/vnd.api+json" } })
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
 * @since 0.1.0
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
      const headers = forwardedHeaders(request, options.headers);
      // The session read is a JSON:API request whatever the inbound request
      // accepted (a browser navigation accepts `text/html`).
      headers.set("accept", MEDIA_TYPE);
      const outbound = new Request(url("/sessions/current?include=user"), {
        method: "GET",
        headers,
      });

      const response = yield* promiseOrDie(() => send(outbound));
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
        // SAFETY: widening `json()`'s `any` to `unknown` only drops trust in the
        // body; `decodeDocument` parses it next.
        try: () => response.json() as Promise<unknown>,
        catch: (cause) =>
          new RemoteSessionError({ message: "Session read body was not JSON", cause }),
      });

      const document = yield* decodeDocument(body).pipe(
        Effect.mapError(
          (cause) => new RemoteSessionError({ message: "Session read body did not decode", cause }),
        ),
      );
      const session = fromSessionDocument(document);
      if (Option.isNone(session)) {
        return yield* new RemoteSessionError({
          message: "Session read body did not include the session's user",
        });
      }

      return { session, setCookie };
    }).pipe(Effect.withSpan(spanNames.remoteSessionRead));

  const apiKeyHeaders = options.credentials?.apiKeyHeaders ?? ["x-api-key"];

  const readApiKey = (request: Request): Effect.Effect<RemoteSessionResult, RemoteSessionError> =>
    Effect.gen(function* () {
      // The key headers ride along (the configured spellings too); the session
      // cookie and a bearer token never do, so the auth service cannot answer
      // for the session instead of the key.
      const headers = forwardedHeaders(request, {
        ...options.headers,
        also: [...(options.headers?.also ?? []), ...apiKeyHeaders],
      });
      headers.delete("cookie");
      if (!Arr.some(apiKeyHeaders, (name) => name.toLowerCase() === "authorization")) {
        headers.delete("authorization");
      }
      headers.set("accept", MEDIA_TYPE);
      const outbound = new Request(url("/api-keys/current"), { method: "GET", headers });

      const response = yield* promiseOrDie(() => send(outbound));

      // A machine caller is never handed a cookie, so none is replayed here.
      // 401 is "ran, the key does not resolve": anonymous, never the cookie.
      if (response.status === 401) return emptyResult;

      if (response.status !== 200) {
        return yield* new RemoteSessionError({
          message: `API key read returned ${response.status}`,
          status: response.status,
        });
      }

      const body = yield* Effect.tryPromise({
        try: () => response.text(),
        catch: (cause) =>
          new RemoteSessionError({ message: "API key read body could not be read", cause }),
      });

      // The JSON parse and the document decode are one step.
      const document = yield* decodeApiKeyDocument(body).pipe(
        Effect.mapError(
          (cause) => new RemoteSessionError({ message: "API key read body did not decode", cause }),
        ),
      );
      const resolved = fromApiKeyDocument(document);
      if (Option.isNone(resolved)) {
        return yield* new RemoteSessionError({
          message: "API key read body did not include the key's user",
        });
      }

      return {
        session: Option.none(),
        setCookie: [],
        user: resolved.value.user,
        apiKey: resolved.value.apiKey,
      };
    }).pipe(Effect.withSpan(spanNames.remoteApiKeyRead));

  const relay = (request: Request, path?: string): Effect.Effect<Response> =>
    Effect.gen(function* () {
      const target = path === undefined ? new URL(request.url).pathname : `${prefix}${path}`;
      const headers = forwardedHeaders(request, options.headers);
      const hasBody = request.method !== "GET" && request.method !== "HEAD";

      // Content headers come from the body being sent, never from the inbound
      // request — see the 415 note at the top of this module.
      const contentType = hasBody ? request.headers.get("content-type") : null;
      if (contentType !== null) headers.set("content-type", contentType);

      const body = hasBody ? yield* promiseOrDie(() => request.arrayBuffer()) : undefined;

      const response = yield* promiseOrDie(() =>
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

  return { credential, read, readApiKey, relay };
};

/**
 * Rebuild an upstream response for the browser, applying the machine-caller
 * rule: `Set-Cookie` is relayed to every caller without a machine credential,
 * and stripped when the inbound request carried an API key or a bearer token
 * (with or without a session cookie beside it). A browser with no cookie yet
 * therefore receives its session cookie on first sign-in (#619). A relayed
 * response that keeps its `Set-Cookie` carries `Cache-Control: no-store`
 * (#628): `no-store` is appended to an upstream `Cache-Control` that lacks it,
 * and one that has it is kept as it is.
 *
 * Exported so an app relaying through its own code path gets the same rule.
 *
 * @since 0.1.0
 * @category constructors
 */
export const relayResponse = (
  upstream: Response,
  inbound: SessionResolution.CredentialPresence,
): Response => {
  const cookies = upstream.headers.getSetCookie();
  if (Arr.isReadonlyArrayEmpty(cookies)) return upstream;

  // A key- or token-bearing caller is not a browser. The mixed case — a
  // request carrying both a cookie and a key or token — is excluded too: the
  // machine credential is its credential, so the session state has nowhere
  // useful to go. A cookie is not required: a first sign-in has none yet.
  const mayReceiveCookies = !inbound.hasApiKey && !inbound.hasBearer;
  if (mayReceiveCookies) return noStoreWithSetCookie(upstream);

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
 * @since 0.1.0
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
 * The read an edge resolution runs (#730): a request carrying an API key is
 * resolved through `GET /api-keys/current`, whatever cookie or bearer token
 * it also carries (the key wins), and a client with no key read fails closed
 * rather than falling back to the session.
 */
const edgeRead = (
  options: ResolveAtEdgeOptions,
  credential: SessionResolution.CredentialPresence,
): Effect.Effect<RemoteSessionResult, RemoteSessionError> => {
  if (!credential.hasApiKey) return options.client.read(options.request);
  const readApiKey = options.client.readApiKey;
  return readApiKey === undefined
    ? Effect.fail(
        new RemoteSessionError({
          message: "This client cannot resolve an API key (no readApiKey)",
        }),
      )
    : readApiKey(options.request);
};

/** Whether an edge read named a caller: a session, or an API key's user. */
const edgeResolved = (result: RemoteSessionResult): boolean =>
  Option.isSome(result.session) || result.user !== undefined;

/**
 * Resolve the session over the transport at an app edge, **failing closed**.
 *
 * Skips the call entirely for a cookieless request, reports the outcome, and
 * carries the `Set-Cookie` lines to replay.
 *
 * A request carrying an API key resolves the key instead (#730), through
 * {@link RemoteSessionClient.readApiKey}: `{ session: None, user, apiKey,
 * credentialClass: "machine" }` for a key that resolves, anonymous for one the
 * auth service refuses with `401`, and a {@link RemoteSessionError} for any
 * other answer, the `404` of an auth service without an `ApiKeyService`
 * included. It never falls back to a cookie the request also carries. Each
 * resolution consumes one use of the key (a non-consuming check is #645).
 *
 * @since 0.1.0
 * @category resolution
 */
export const resolveAtEdge = (
  options: ResolveAtEdgeOptions,
): Effect.Effect<EdgeSession, RemoteSessionError> => {
  const credential = options.client.credential(options.request);
  return Effect.map(
    SessionResolution.resolveWith({
      credential,
      resolve: edgeRead(options, credential),
      session: (result) => result.session,
      resolved: edgeResolved,
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
 * A request carrying an API key resolves the key as {@link resolveAtEdge}
 * does (#730), consuming one use of it; a fault on that path, the `404` of an
 * auth service without an `ApiKeyService` included, degrades to anonymous,
 * never to a session cookie the request also carries.
 *
 * @example A Worker front door
 * ```ts
 * import assert from "node:assert/strict"
 * import { Effect } from "effect"
 * import * as Option from "effect/Option"
 * import { SessionCookies } from "@thomasfosterau/effect-auth"
 * import * as Http from "@thomasfosterau/effect-auth/http"
 *
 * // A stand-in for the auth worker behind the service binding: it answers the
 * // session read for any request carrying a cookie.
 * const authWorker = async (request: Request): Promise<Response> => {
 *   const { pathname } = new URL(request.url)
 *   if (request.method === "GET" && pathname.endsWith("/sessions/current")) {
 *     if (request.headers.get("cookie") === null) return new Response(null, { status: 401 })
 *     // `GET /sessions/current?include=user`: the session, its user included.
 *     const document = {
 *       data: {
 *         type: "sessions",
 *         id: "session-1",
 *         attributes: {
 *           expiresAt: 4_102_444_800_000,
 *           createdAt: 1_700_000_000_000,
 *           lastActivityAt: 1_700_000_000_000,
 *           attributes: {},
 *         },
 *         relationships: { user: { data: { type: "users", id: "u-1" } } },
 *       },
 *       included: [
 *         {
 *           type: "users",
 *           id: "u-1",
 *           attributes: {
 *             email: "user@example.com",
 *             emailVerified: true,
 *             createdAt: 1_700_000_000_000,
 *             updatedAt: 1_700_000_000_000,
 *             attributes: {},
 *           },
 *         },
 *       ],
 *     }
 *     return Response.json(document, { headers: { "content-type": "application/vnd.api+json" } })
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
 * @since 0.1.0
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
      resolve: edgeRead(options, credential),
      session: (result) => result.session,
      resolved: edgeResolved,
      empty: emptyResult,
      onDegraded: options.onDegraded,
    }),
    toEdge(credential),
  );
};

/**
 * Replay relayed `Set-Cookie` lines onto an outgoing response, marking it
 * `Cache-Control: no-store` as {@link relayResponse} does (#628).
 *
 * @since 0.1.0
 * @category constructors
 */
export const withSetCookie = (response: Response, setCookie: ReadonlyArray<string>): Response => {
  if (Arr.isReadonlyArrayEmpty(setCookie)) return response;
  const headers = new Headers(response.headers);
  setCookie.forEach((cookie) => headers.append("set-cookie", cookie));
  return noStoreWithSetCookie(
    new Response(response.body, {
      status: response.status,
      statusText: response.statusText,
      headers,
    }),
  );
};
