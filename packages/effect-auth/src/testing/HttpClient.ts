/**
 * Test support: an `HttpClient` over whatever `globalThis.fetch` is when a
 * request is sent, so a suite that swaps the global still intercepts the
 * core's outbound requests. `FetchHttpClient`'s own default reads the global
 * once and keeps it.
 */
import { Effect, type Exit, Layer } from "effect";
import { FetchHttpClient, type HttpClient } from "effect/http";

export const globalFetchHttpClient = FetchHttpClient.layer.pipe(
  Layer.provide(
    Layer.succeed(FetchHttpClient.Fetch, (input, init) => globalThis.fetch(input, init)),
  ),
);

/** `Effect.runPromise` with {@link globalFetchHttpClient} provided. */
export const runPromiseHttp = <A, E>(
  effect: Effect.Effect<A, E, HttpClient.HttpClient>,
): Promise<A> => Effect.runPromise(Effect.provide(effect, globalFetchHttpClient));

/** `Effect.runPromiseExit` with {@link globalFetchHttpClient} provided. */
export const runPromiseExitHttp = <A, E>(
  effect: Effect.Effect<A, E, HttpClient.HttpClient>,
): Promise<Exit.Exit<A, E>> => Effect.runPromiseExit(Effect.provide(effect, globalFetchHttpClient));
