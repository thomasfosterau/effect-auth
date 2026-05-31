import { HttpApi, HttpApiEndpoint, HttpApiGroup, HttpApiSchema } from "effect/unstable/httpapi";
import * as S from "./HttpApiSchemas.js";

/**
 * The auth HTTP contract.
 *
 * This is the single source of truth for the protocol: it derives the server
 * (see `HttpServer.ts`), a typed Effect-native client (see `HttpClient.ts`),
 * and an OpenAPI document. Mounted under a configurable prefix (default
 * `/api/auth`).
 */

/** Email/password + session endpoints. */
export const authGroup = HttpApiGroup.make("auth").add(
  HttpApiEndpoint.post("signUp", "/sign-up", {
    payload: S.SignUpPayload,
    success: S.AuthSuccess,
    error: [S.ConflictError, S.BadRequestError, S.InternalError],
  }),
  HttpApiEndpoint.post("signIn", "/sign-in", {
    payload: S.SignInPayload,
    success: S.AuthSuccess,
    error: [S.UnauthorizedError, S.ForbiddenError, S.InternalError],
  }),
  HttpApiEndpoint.post("signOut", "/sign-out", {
    success: HttpApiSchema.NoContent,
  }),
  HttpApiEndpoint.get("getSession", "/session", {
    success: S.SessionWithUserView,
    error: [S.UnauthorizedError],
  }),
);

/** The complete auth API. */
export const AuthApi = HttpApi.make("AuthApi").add(authGroup);
