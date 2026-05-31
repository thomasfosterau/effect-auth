import { HttpApiClient } from "effect/unstable/httpapi";
import { AuthApi } from "./HttpApi.js";

/**
 * Derive a typed, Effect-native client for the auth API.
 *
 * Returns an `Effect` that yields the client; it requires an
 * `HttpClient.HttpClient` in context (e.g. provide `FetchHttpClient.layer`).
 * Client methods return `Effect`s over the same `Schema` types and tagged-error
 * channel as the server contract.
 *
 * @example
 * ```ts
 * const program = Effect.gen(function* () {
 *   const client = yield* makeAuthClient("http://localhost:5173");
 *   const result = yield* client.auth.signIn({ payload: { email, password } });
 * });
 * ```
 */
export const makeAuthClient = (baseUrl: string | URL) => HttpApiClient.make(AuthApi, { baseUrl });
