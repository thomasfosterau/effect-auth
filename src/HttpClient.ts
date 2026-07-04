import { HttpApiClient } from "effect/unstable/httpapi";
import { AuthApi } from "./HttpApi.ts";

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
 * import { Effect } from "effect"
 * import { Http } from "effect-auth"
 *
 * const program = Effect.gen(function* () {
 *   const client = yield* Http.makeAuthClient("http://localhost:5173")
 *   const result = yield* client.auth.signIn({
 *     payload: { email: "user@example.com", password: "password-123" },
 *   })
 *   return result.user
 * })
 * ```
 */
export const makeAuthClient = (baseUrl: string | URL) => HttpApiClient.make(AuthApi, { baseUrl });
