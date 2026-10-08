import { HttpApiClient } from "effect/http-api";
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
 * import assert from "node:assert/strict"
 * import { Effect, Layer } from "effect"
 * import { FetchHttpClient } from "effect/http"
 * import { Http } from "@thomasfosterau/effect-auth"
 *
 * // A stand-in for the auth service at http://localhost:5173, answering in-process.
 * const authService = async (request: Request): Promise<Response> => {
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
 *
 * const program = Effect.gen(function* () {
 *   const client = yield* Http.client("http://localhost:5173")
 *   const result = yield* client.auth.signIn({
 *     payload: { email: "user@example.com", password: "password-123" },
 *   })
 *   return result.user
 * }).pipe(
 *   Effect.provide(
 *     FetchHttpClient.layer.pipe(
 *       Layer.provide(
 *         Layer.succeed(FetchHttpClient.Fetch, (input, init) =>
 *           authService(new Request(input, init)),
 *         ),
 *       ),
 *     ),
 *   ),
 * )
 *
 * const user = await Effect.runPromise(program)
 * assert.equal(user.id, "u-1")
 * ```
 */
export const client = (baseUrl: string | URL) => HttpApiClient.make(AuthApi, { baseUrl });
