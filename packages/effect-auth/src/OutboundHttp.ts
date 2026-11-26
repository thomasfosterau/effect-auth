/**
 * The bounds on every request the core sends: one timeout over the whole
 * exchange, a cap on the response body, and no redirects. Requests go through
 * the application's `HttpClient`; override the limits by providing {@link
 * OutboundLimits} where the services' layers are built.
 *
 * @example
 * ```ts
 * import assert from "node:assert/strict"
 * import { Effect, Layer } from "effect"
 * import { OutboundHttp } from "@thomasfosterau/effect-auth"
 *
 * // Tighter bounds for every outbound request the core's layers make.
 * const Limits = Layer.succeed(OutboundHttp.OutboundLimits, { timeoutMs: 3_000, maxBodyBytes: 65_536 })
 *
 * const limits = await Effect.runPromise(
 *   Effect.gen(function* () {
 *     return yield* OutboundHttp.OutboundLimits
 *   }).pipe(Effect.provide(Limits)),
 * )
 * assert.equal(limits.timeoutMs, 3_000)
 * ```
 *
 * @since 0.9.0
 */
import { Context, Data, Duration, Effect } from "effect";
import * as Option from "effect/Option";
import * as Schema from "effect/Schema";
import * as Stream from "effect/Stream";
import {
  FetchHttpClient,
  HttpClient,
  HttpClientRequest,
  type Headers,
  type HttpClientResponse,
} from "effect/http";
import * as RemoteJwks from "./RemoteJwks.ts";

/**
 * The bounds on one outbound request.
 *
 * @since 0.9.0
 * @category models
 */
export interface Limits {
  /** The whole exchange, from sending to the last body byte. */
  readonly timeoutMs: number;
  /** The largest response body read; a longer one fails the request. */
  readonly maxBodyBytes: number;
}

/**
 * The default {@link Limits}: 10 seconds and 1 MiB, ample for the JSON
 * documents (JWKS, discovery, token and userinfo responses) the core reads.
 *
 * @since 0.9.0
 * @category constants
 */
export const defaultLimits: Limits = { timeoutMs: 10_000, maxBodyBytes: 1_048_576 };

/**
 * The {@link Limits} the core's layers read when they are built. Provide it
 * to change them; without it, {@link defaultLimits} apply.
 *
 * @since 0.9.0
 * @category references
 */
export const OutboundLimits: Context.Reference<Limits> = Context.Reference<Limits>(
  "@effect-auth/OutboundLimits",
  { defaultValue: () => defaultLimits },
);

/**
 * An outbound request that could not complete: its URL failed the caller's
 * policy and was never sent (`"refused-url"`), it could not be sent
 * (`"transport"`), it ran past the timeout (`"timeout"`), or it answered a
 * body over the cap (`"too-large"`).
 *
 * @since 0.9.0
 * @category errors
 */
export class OutboundHttpError extends Data.TaggedError("OutboundHttpError")<{
  readonly reason: "refused-url" | "transport" | "timeout" | "too-large";
  readonly message: string;
  readonly cause?: unknown;
}> {}

/**
 * A response read within the {@link Limits}: its status, headers and body as
 * text. A redirect is not followed, so it arrives as its `3xx` (or, from a
 * browser's `fetch`, status `0`), which no caller treats as success.
 *
 * @since 0.9.0
 * @category models
 */
export interface Response {
  readonly status: number;
  readonly headers: Headers.Headers;
  readonly body: string;
}

/**
 * A check a URL must pass before a request to it is sent: the reason it is
 * refused, or `undefined`.
 */
export type UrlPolicy = (url: string) => string | undefined;

/** The policy that refuses nothing. */
export const allowAnyUrl: UrlPolicy = () => undefined;

/** The {@link UrlPolicy} {@link sendWith} applies; a service providing its own sets it. */
export const OutboundUrlPolicy: Context.Reference<UrlPolicy> = Context.Reference<UrlPolicy>(
  "@effect-auth/OutboundUrlPolicy",
  { defaultValue: () => allowAnyUrl },
);

/** A `GET` that asks for JSON. */
export const getJson = (url: string): HttpClientRequest.HttpClientRequest =>
  HttpClientRequest.get(url).pipe(HttpClientRequest.acceptJson);

/** Whether a response is a 2xx. */
export const isOk = (response: { readonly status: number }): boolean =>
  response.status >= 200 && response.status < 300;

const tooLarge = (maxBodyBytes: number) =>
  new OutboundHttpError({
    reason: "too-large",
    message: `Response body exceeds ${maxBodyBytes} bytes`,
  });

/**
 * The body, failing once it passes `maxBodyBytes`: early on a declared
 * `content-length`, else as the bytes arrive.
 */
const readCapped = (
  response: HttpClientResponse.HttpClientResponse,
  maxBodyBytes: number,
): Effect.Effect<string, OutboundHttpError> => {
  const declared = Number(response.headers["content-length"] ?? Number.NaN);
  if (Number.isFinite(declared) && declared > maxBodyBytes) {
    return Effect.fail(tooLarge(maxBodyBytes));
  }
  return response.stream.pipe(
    Stream.mapError(
      (cause) =>
        new OutboundHttpError({
          reason: "transport",
          message: "Failed to read the response",
          cause,
        }),
    ),
    Stream.runFoldEffect(
      (): { readonly chunks: ReadonlyArray<Uint8Array>; readonly size: number } => ({
        chunks: [],
        size: 0,
      }),
      (acc, chunk) =>
        acc.size + chunk.byteLength > maxBodyBytes
          ? Effect.fail(tooLarge(maxBodyBytes))
          : Effect.succeed({ chunks: [...acc.chunks, chunk], size: acc.size + chunk.byteLength }),
    ),
    Effect.map(({ chunks, size }) => {
      const bytes = new Uint8Array(size);
      chunks.reduce((offset, chunk) => {
        bytes.set(chunk, offset);
        return offset + chunk.byteLength;
      }, 0);
      return new TextDecoder().decode(bytes);
    }),
  );
};

/**
 * `fetch` follows redirects itself unless told otherwise; a followed redirect
 * would replay a token request's client secret, or reach a host the URL
 * policy never saw. Other clients see the `RequestInit` service not at all.
 */
const refuseRedirects = <A, E, R>(effect: Effect.Effect<A, E, R>): Effect.Effect<A, E, R> =>
  Effect.flatMap(Effect.serviceOption(FetchHttpClient.RequestInit), (init) =>
    effect.pipe(
      Effect.provideService(FetchHttpClient.RequestInit, {
        ...Option.getOrElse(init, () => ({})),
        redirect: "manual",
      }),
    ),
  );

/**
 * `client` with redirects refused before they are sent, for a library that
 * sends through the `HttpClient` itself (`effect/jose`'s remote key set).
 *
 * @since 0.9.0
 * @category requests
 */
export const withoutRedirects = <E, R>(
  client: HttpClient.HttpClient.With<E, R>,
): HttpClient.HttpClient.With<E, R> => HttpClient.transform(client, refuseRedirects);

/**
 * Send `request` through `client` and read the response within `limits`.
 *
 * @since 0.9.0
 * @category requests
 */
export const send = (
  client: HttpClient.HttpClient,
  request: HttpClientRequest.HttpClientRequest,
  limits: Limits,
  urlPolicy: UrlPolicy = allowAnyUrl,
): Effect.Effect<Response, OutboundHttpError> => {
  const refusal = urlPolicy(request.url);
  if (refusal !== undefined) {
    return Effect.fail(new OutboundHttpError({ reason: "refused-url", message: refusal }));
  }
  return client.execute(request).pipe(
    Effect.mapError(
      (cause) =>
        new OutboundHttpError({
          reason: "transport",
          message: "Failed to send the request",
          cause,
        }),
    ),
    Effect.flatMap((response) =>
      Effect.map(readCapped(response, limits.maxBodyBytes), (body) => ({
        status: response.status,
        headers: response.headers,
        body,
      })),
    ),
    refuseRedirects,
    Effect.timeoutOrElse({
      duration: Duration.millis(limits.timeoutMs),
      orElse: () =>
        Effect.fail(
          new OutboundHttpError({
            reason: "timeout",
            message: `No complete response within ${limits.timeoutMs} ms`,
          }),
        ),
    }),
  );
};

/**
 * {@link send} with the client and limits from context, for the functions
 * (provider methods, `verifyIdToken`) that services call with theirs
 * provided.
 */
export const sendWith = (
  request: HttpClientRequest.HttpClientRequest,
): Effect.Effect<Response, OutboundHttpError, HttpClient.HttpClient> =>
  Effect.gen(function* () {
    const client = yield* HttpClient.HttpClient;
    const limits = yield* OutboundLimits;
    const urlPolicy = yield* OutboundUrlPolicy;
    return yield* send(client, request, limits, urlPolicy);
  });

/**
 * What a service resolves when its layer is built: the client, the limits,
 * and its own cache of remote key sets (for `verifyIdToken`).
 */
export interface Outbound {
  readonly client: HttpClient.HttpClient;
  readonly limits: Limits;
  readonly keySets: typeof RemoteJwks.KeySets.Service;
  readonly urlPolicy: UrlPolicy;
}

/** Resolve an {@link Outbound}, once, where a layer is built. */
export const resolve = (
  urlPolicy: UrlPolicy = allowAnyUrl,
): Effect.Effect<Outbound, never, HttpClient.HttpClient> =>
  Effect.gen(function* () {
    return {
      client: yield* HttpClient.HttpClient,
      limits: yield* OutboundLimits,
      keySets: yield* RemoteJwks.makeKeySets(),
      urlPolicy,
    };
  });

/** Run `effect` with a service's resolved client, limits and key sets. */
export const provide =
  (outbound: Outbound) =>
  <A, E, R>(
    effect: Effect.Effect<A, E, R>,
  ): Effect.Effect<A, E, Exclude<Exclude<R, HttpClient.HttpClient>, RemoteJwks.KeySets>> =>
    effect.pipe(
      Effect.provideService(HttpClient.HttpClient, outbound.client),
      Effect.provideService(OutboundLimits, outbound.limits),
      Effect.provideService(RemoteJwks.KeySets, outbound.keySets),
      Effect.provideService(OutboundUrlPolicy, outbound.urlPolicy),
    );

/**
 * `effect` with the client and limits now in context fixed, for an effect
 * kept and run later outside it (a cached key set's fetch).
 */
export const provideCurrent = <A, E>(
  effect: Effect.Effect<A, E, HttpClient.HttpClient>,
): Effect.Effect<Effect.Effect<A, E>, never, HttpClient.HttpClient> =>
  Effect.gen(function* () {
    return {
      client: yield* HttpClient.HttpClient,
      limits: yield* OutboundLimits,
      urlPolicy: yield* OutboundUrlPolicy,
    };
  }).pipe(
    Effect.map(({ client, limits, urlPolicy }) =>
      effect.pipe(
        Effect.provideService(HttpClient.HttpClient, client),
        Effect.provideService(OutboundLimits, limits),
        Effect.provideService(OutboundUrlPolicy, urlPolicy),
      ),
    ),
  );

const decodeJsonString = Schema.decodeUnknownEffect(Schema.fromJsonString(Schema.Json));

/** A body parsed as JSON. */
export const parseJson = (body: string): Effect.Effect<Schema.Json, Schema.SchemaError> =>
  decodeJsonString(body);

/** How much of an upstream body a log line keeps. */
const LOG_EXCERPT_CHARS = 512;

/**
 * Log a provider's non-2xx answer, the body cut to an excerpt, at warning
 * level. The excerpt goes only to the log, never into an error message a
 * client could be shown.
 */
export const logUpstreamFailure = (
  what: string,
  response: Response,
  annotations: Record<string, string> = {},
): Effect.Effect<void> =>
  Effect.logWarning(`${what}: upstream answered ${response.status}`).pipe(
    Effect.annotateLogs({
      ...annotations,
      status: `${response.status}`,
      body: response.body.slice(0, LOG_EXCERPT_CHARS),
    }),
  );
