/**
 * HTTP protocol for effect-auth (optional; requires `effect/unstable/httpapi`).
 *
 * Re-exported from the package root under the `HTTP` namespace, e.g.
 * `Auth.HTTP.AuthApi`, `Auth.HTTP.make`, `Auth.HTTP.client`.
 * Also available as the `effect-auth/http` subpath export.
 */

/** Wire schemas, views, encoders, and HTTP error types. */
export * from "./HTTPApiSchemas.ts";

/** The `AuthApi` contract (groups + endpoints). */
export * from "./HTTPApi.ts";

/** Server: handler layers and the mountable web handler. */
export * from "./HTTPServer.ts";

/** Signed session-data cookie cache (config + codec). */
export * from "../SessionCookieCache.ts";

/** Typed, Effect-native client. */
export * from "./HTTPClient.ts";

/** Composable HttpApiMiddleware for consumer apps (AuthMiddleware, OptionalAuthMiddleware, …). */
export * from "./HTTPMiddleware.ts";
