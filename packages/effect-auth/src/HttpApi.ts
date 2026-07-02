import { Schema } from "effect";
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
  HttpApiEndpoint.post("sendVerificationEmail", "/email-verification/send", {
    payload: S.SendVerificationEmailPayload,
    success: S.StatusResponse,
    error: [S.BadRequestError, S.InternalError],
  }),
  HttpApiEndpoint.post("verifyEmail", "/email-verification/verify", {
    payload: S.VerifyEmailPayload,
    success: S.AuthSuccess,
    error: [S.BadRequestError, S.InternalError],
  }),
  HttpApiEndpoint.post("requestPasswordReset", "/password-reset/request", {
    payload: S.RequestPasswordResetPayload,
    success: S.StatusResponse,
    error: [S.BadRequestError, S.InternalError],
  }),
  HttpApiEndpoint.post("resetPassword", "/password-reset/reset", {
    payload: S.ResetPasswordPayload,
    success: S.StatusResponse,
    error: [S.BadRequestError, S.InternalError],
  }),
  HttpApiEndpoint.post("changePassword", "/change-password", {
    payload: S.ChangePasswordPayload,
    success: HttpApiSchema.NoContent,
    error: [S.UnauthorizedError, S.BadRequestError, S.InternalError],
  }),
  HttpApiEndpoint.patch("updateUser", "/user", {
    payload: S.UpdateUserPayload,
    success: S.UserView,
    error: [S.UnauthorizedError, S.InternalError],
  }),
  HttpApiEndpoint.get("listSessions", "/sessions", {
    success: S.SessionListView,
    error: [S.UnauthorizedError, S.InternalError],
  }),
  HttpApiEndpoint.delete("revokeSession", "/sessions/:sessionId", {
    params: { sessionId: Schema.String },
    success: HttpApiSchema.NoContent,
    error: [S.UnauthorizedError, S.BadRequestError, S.InternalError],
  }),
  HttpApiEndpoint.post("revokeOtherSessions", "/sessions/revoke-others", {
    success: HttpApiSchema.NoContent,
    error: [S.UnauthorizedError, S.InternalError],
  }),
);

/** The complete auth API. */
export const AuthApi = HttpApi.make("AuthApi").add(authGroup);
