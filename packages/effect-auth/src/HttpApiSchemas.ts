import { Schema } from "effect";
import { HttpApiSchema } from "effect/unstable/httpapi";
import type * as Types from "./Types.js";

/**
 * HTTP wire schemas for the auth protocol.
 *
 * The core domain types (`Types.User`, `Types.Session`, ...) are plain
 * TypeScript interfaces. The HTTP layer needs `Schema`s to encode/decode over
 * the wire and to derive a typed client, so we define `*View` schemas here
 * alongside small encoders that bridge the domain types to them. Timestamps are
 * represented as epoch milliseconds (numbers) to keep JSON encoding trivial.
 */

/** Arbitrary JSON attributes bag. */
export const Attributes = Schema.Record(Schema.String, Schema.Unknown);

/** Public view of a user (timestamps as epoch millis). */
export const UserView = Schema.Struct({
  id: Schema.String,
  email: Schema.String,
  emailVerified: Schema.Boolean,
  name: Schema.optional(Schema.String),
  image: Schema.optional(Schema.String),
  createdAt: Schema.Number,
  updatedAt: Schema.Number,
  attributes: Attributes,
});
export type UserView = typeof UserView.Type;

/** Public view of a session (timestamps as epoch millis). */
export const SessionView = Schema.Struct({
  id: Schema.String,
  userId: Schema.String,
  expiresAt: Schema.Number,
  createdAt: Schema.Number,
  lastActivityAt: Schema.Number,
  attributes: Attributes,
});
export type SessionView = typeof SessionView.Type;

/** A session together with its user. */
export const SessionWithUserView = Schema.Struct({
  session: SessionView,
  user: UserView,
});
export type SessionWithUserView = typeof SessionWithUserView.Type;

/** Request body for sign-up. */
export const SignUpPayload = Schema.Struct({
  email: Schema.String,
  password: Schema.String,
  name: Schema.optional(Schema.String),
  attributes: Schema.optional(Attributes),
});
export type SignUpPayload = typeof SignUpPayload.Type;

/** Request body for sign-in. */
export const SignInPayload = Schema.Struct({
  email: Schema.String,
  password: Schema.String,
});
export type SignInPayload = typeof SignInPayload.Type;

/**
 * Successful authentication result. The session itself is conveyed via the
 * session cookie (`Set-Cookie`); `needsEmailVerification` lets a client branch
 * when verification is still required.
 */
export const AuthSuccess = Schema.Struct({
  user: UserView,
  needsEmailVerification: Schema.Boolean,
});
export type AuthSuccess = typeof AuthSuccess.Type;

/**
 * Generic acknowledgement for operations that intentionally do not reveal
 * outcome details (e.g. anti-enumeration email flows).
 */
export const StatusResponse = Schema.Struct({
  status: Schema.Boolean,
});
export type StatusResponse = typeof StatusResponse.Type;

/** Request body for sending/resending an email verification. */
export const SendVerificationEmailPayload = Schema.Struct({
  email: Schema.String,
});
export type SendVerificationEmailPayload = typeof SendVerificationEmailPayload.Type;

/** Request body for verifying an email with a token. */
export const VerifyEmailPayload = Schema.Struct({
  token: Schema.String,
});
export type VerifyEmailPayload = typeof VerifyEmailPayload.Type;

/** Request body for requesting a password reset email. */
export const RequestPasswordResetPayload = Schema.Struct({
  email: Schema.String,
});
export type RequestPasswordResetPayload = typeof RequestPasswordResetPayload.Type;

/** Request body for completing a password reset. */
export const ResetPasswordPayload = Schema.Struct({
  token: Schema.String,
  newPassword: Schema.String,
});
export type ResetPasswordPayload = typeof ResetPasswordPayload.Type;

/** Request body for changing the authenticated user's password. */
export const ChangePasswordPayload = Schema.Struct({
  currentPassword: Schema.String,
  newPassword: Schema.String,
  revokeOtherSessions: Schema.optional(Schema.Boolean),
});
export type ChangePasswordPayload = typeof ChangePasswordPayload.Type;

/** Request body for updating the authenticated user's profile. */
export const UpdateUserPayload = Schema.Struct({
  name: Schema.optional(Schema.String),
  image: Schema.optional(Schema.String),
});
export type UpdateUserPayload = typeof UpdateUserPayload.Type;

/** List of the authenticated user's active sessions. */
export const SessionListView = Schema.Array(SessionView);
export type SessionListView = typeof SessionListView.Type;

// -----------------------------------------------------------------------------
// Error schemas (mapped to HTTP status codes via HttpApiSchema.status)
// -----------------------------------------------------------------------------

/** 401 — missing/invalid credentials or session. */
export class Unauthorized extends Schema.TaggedErrorClass<Unauthorized>()("Unauthorized", {
  message: Schema.String,
}) {}

/** 403 — authenticated but not allowed (e.g. email not verified). */
export class Forbidden extends Schema.TaggedErrorClass<Forbidden>()("Forbidden", {
  message: Schema.String,
}) {}

/** 409 — conflict (e.g. user already exists). */
export class Conflict extends Schema.TaggedErrorClass<Conflict>()("Conflict", {
  message: Schema.String,
}) {}

/** 400 — malformed/invalid request. */
export class BadRequest extends Schema.TaggedErrorClass<BadRequest>()("BadRequest", {
  message: Schema.String,
}) {}

/** 500 — unexpected server error. */
export class InternalServerError extends Schema.TaggedErrorClass<InternalServerError>()(
  "InternalServerError",
  { message: Schema.String },
) {}

/** Each error class paired with its HTTP status for use in endpoint `error` fields. */
export const UnauthorizedError = Unauthorized.pipe(HttpApiSchema.status(401));
export const ForbiddenError = Forbidden.pipe(HttpApiSchema.status(403));
export const ConflictError = Conflict.pipe(HttpApiSchema.status(409));
export const BadRequestError = BadRequest.pipe(HttpApiSchema.status(400));
export const InternalError = InternalServerError.pipe(HttpApiSchema.status(500));

// -----------------------------------------------------------------------------
// Encoders: domain types -> wire views
// -----------------------------------------------------------------------------

export const encodeUser = (user: Types.User): UserView => ({
  id: user.id,
  email: user.email,
  emailVerified: user.emailVerified,
  ...(user.name !== undefined && { name: user.name }),
  ...(user.image !== undefined && { image: user.image }),
  createdAt: user.createdAt.getTime(),
  updatedAt: user.updatedAt.getTime(),
  attributes: user.attributes,
});

export const encodeSession = (session: Types.Session): SessionView => ({
  id: session.id,
  userId: session.userId,
  expiresAt: session.expiresAt.getTime(),
  createdAt: session.createdAt.getTime(),
  lastActivityAt: session.lastActivityAt.getTime(),
  attributes: session.attributes,
});

export const encodeSessionWithUser = (value: Types.SessionWithUser): SessionWithUserView => ({
  session: encodeSession(value.session),
  user: encodeUser(value.user),
});
