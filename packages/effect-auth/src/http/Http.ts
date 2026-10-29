/**
 * HTTP protocol for effect-auth (optional; requires `effect/http-api`).
 *
 * Published only as the `@thomasfosterau/effect-auth/http` subpath, never from
 * the package root, so the headless core stays free of `effect/http-api`:
 * `import * as Http from "@thomasfosterau/effect-auth/http"`, then
 * `Http.AuthApi`, `Http.make`, `Http.client`.
 */

/** Wire schemas, views, encoders, and HTTP error types. */
export * from "./HttpApiSchema.ts";

/** The `AuthApi` contract (groups + endpoints). */
export * from "./HttpApi.ts";

/** Server: handler layers and the mountable web handler. */
export * from "./HttpServer.ts";

/** Signed session-data cookie cache (config + codec). */
export * from "../SessionCookieCache.ts";

/** Typed, Effect-native client. */
export * from "./HttpClient.ts";

/** Composable HttpApiMiddleware for consumer apps (AuthMiddleware, OptionalAuthMiddleware, …). */
export * from "./HttpMiddleware.ts";
