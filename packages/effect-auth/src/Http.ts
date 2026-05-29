/**
 * HTTP protocol for effect-auth (optional; requires `effect/unstable/httpapi`).
 *
 * Re-exported from the package root under the `Http` namespace, e.g.
 * `Auth.Http.AuthApi`, `Auth.Http.makeAuthWebHandler`, `Auth.Http.makeAuthClient`.
 */

/** Wire schemas, views, encoders, and HTTP error types. */
export * from "./HttpApiSchemas.js";

/** The `AuthApi` contract (groups + endpoints). */
export * from "./HttpApi.js";

/** Server: handler layers and the mountable web handler. */
export * from "./HttpServer.js";

/** Typed, Effect-native client. */
export * from "./HttpClient.js";
