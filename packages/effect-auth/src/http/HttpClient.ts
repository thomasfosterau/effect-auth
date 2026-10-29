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
 * import * as Http from "@thomasfosterau/effect-auth/http"
 *
 * // A stand-in for the auth service at http://localhost:5173, answering in-process.
 * const authService = async (request: Request): Promise<Response> => {
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
 *
 * const program = Effect.gen(function* () {
 *   const client = yield* Http.client("http://localhost:5173")
 *   // Sign in: `POST /sessions` with a password credential.
 *   const result = yield* client.sessions.create({
 *     payload: {
 *       data: {
 *         type: "sessions",
 *         attributes: {
 *           credential: { method: "password", email: "user@example.com", password: "password-123" },
 *         },
 *       },
 *     },
 *   })
 *   // A `201` carries the session, its user included; a `202` carries neither.
 *   return "included" in result ? result.included?.[0] : undefined
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
 * assert.equal(user?.id, "u-1")
 * ```
 */
export const client = (baseUrl: string | URL) => HttpApiClient.make(AuthApi, { baseUrl });
