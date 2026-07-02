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

/** A pending second-factor challenge returned instead of a session. */
export const SecondFactorChallengeView = Schema.Struct({
  token: Schema.String,
  expiresAt: Schema.Number,
});
export type SecondFactorChallengeView = typeof SecondFactorChallengeView.Type;

/**
 * Successful authentication result. The session itself is conveyed via the
 * session cookie (`Set-Cookie`); `needsEmailVerification` lets a client branch
 * when verification is still required, and `secondFactor` is present when the
 * user must redeem a two-factor challenge to obtain a session.
 */
export const AuthSuccess = Schema.Struct({
  user: UserView,
  needsEmailVerification: Schema.Boolean,
  secondFactor: Schema.optional(SecondFactorChallengeView),
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

/** Request body for requesting a magic link email. */
export const MagicLinkSendPayload = Schema.Struct({
  email: Schema.String,
});
export type MagicLinkSendPayload = typeof MagicLinkSendPayload.Type;

/** Request body for redeeming a magic link token. */
export const MagicLinkVerifyPayload = Schema.Struct({
  token: Schema.String,
});
export type MagicLinkVerifyPayload = typeof MagicLinkVerifyPayload.Type;

/** Request body for requesting an email change (authenticated). */
export const ChangeEmailRequestPayload = Schema.Struct({
  newEmail: Schema.String,
});
export type ChangeEmailRequestPayload = typeof ChangeEmailRequestPayload.Type;

/** Request body for confirming an email change by token. */
export const ChangeEmailConfirmPayload = Schema.Struct({
  token: Schema.String,
});
export type ChangeEmailConfirmPayload = typeof ChangeEmailConfirmPayload.Type;

/** Request body for confirming account deletion by token. */
export const DeleteUserConfirmPayload = Schema.Struct({
  token: Schema.String,
});
export type DeleteUserConfirmPayload = typeof DeleteUserConfirmPayload.Type;

/** The purposes an email OTP can be issued for. */
export const EmailOtpPurpose = Schema.Literals([
  "sign-in",
  "email-verification",
  "forget-password",
]);
export type EmailOtpPurpose = typeof EmailOtpPurpose.Type;

/** Request body for sending an email OTP. */
export const EmailOtpSendPayload = Schema.Struct({
  email: Schema.String,
  purpose: EmailOtpPurpose,
});
export type EmailOtpSendPayload = typeof EmailOtpSendPayload.Type;

/** The purposes a phone OTP can be issued for. */
export const PhoneOtpPurpose = Schema.Literals(["sign-in", "phone-verification"]);
export type PhoneOtpPurpose = typeof PhoneOtpPurpose.Type;

/** Request body for sending a phone (SMS) OTP. */
export const PhoneOtpSendPayload = Schema.Struct({
  phoneNumber: Schema.String,
  purpose: PhoneOtpPurpose,
});
export type PhoneOtpSendPayload = typeof PhoneOtpSendPayload.Type;

/** Request body for signing in with a phone OTP. */
export const PhoneOtpSignInPayload = Schema.Struct({
  phoneNumber: Schema.String,
  otp: Schema.String,
});
export type PhoneOtpSignInPayload = typeof PhoneOtpSignInPayload.Type;

/** Request body for starting a device authorization request. */
export const DeviceCodePayload = Schema.Struct({
  clientId: Schema.optional(Schema.String),
  scopes: Schema.optional(Schema.Array(Schema.String)),
});
export type DeviceCodePayload = typeof DeviceCodePayload.Type;

/** Response for a started device authorization request. */
export const DeviceCodeView = Schema.Struct({
  deviceCode: Schema.String,
  userCode: Schema.String,
  verificationUri: Schema.String,
  expiresIn: Schema.Number,
  interval: Schema.Number,
});
export type DeviceCodeView = typeof DeviceCodeView.Type;

/** Request body for polling the device token endpoint. */
export const DeviceTokenPayload = Schema.Struct({
  deviceCode: Schema.String,
});
export type DeviceTokenPayload = typeof DeviceTokenPayload.Type;

/** Request body for approving/denying a device user code. */
export const DeviceUserCodePayload = Schema.Struct({
  userCode: Schema.String,
});
export type DeviceUserCodePayload = typeof DeviceUserCodePayload.Type;

/** Request body for signing in with a username + password. */
export const UsernameSignInPayload = Schema.Struct({
  username: Schema.String,
  password: Schema.String,
});
export type UsernameSignInPayload = typeof UsernameSignInPayload.Type;

/** Request body for signing in with an email OTP. */
export const EmailOtpSignInPayload = Schema.Struct({
  email: Schema.String,
  otp: Schema.String,
});
export type EmailOtpSignInPayload = typeof EmailOtpSignInPayload.Type;

/**
 * Request body for two-factor operations that re-verify the user's password
 * (enable, disable, regenerate backup codes).
 */
export const TwoFactorPasswordPayload = Schema.Struct({
  password: Schema.String,
});
export type TwoFactorPasswordPayload = typeof TwoFactorPasswordPayload.Type;

/** Request body for confirming two-factor enrollment with a TOTP code. */
export const TwoFactorConfirmPayload = Schema.Struct({
  code: Schema.String,
});
export type TwoFactorConfirmPayload = typeof TwoFactorConfirmPayload.Type;

/**
 * Request body for redeeming a pending second-factor challenge: the challenge
 * `token` (from sign-in's `secondFactor`) plus a TOTP or backup `code`.
 */
export const TwoFactorVerifyPayload = Schema.Struct({
  token: Schema.String,
  code: Schema.String,
});
export type TwoFactorVerifyPayload = typeof TwoFactorVerifyPayload.Type;

/**
 * Result of enabling two-factor. The secret and backup codes are returned in
 * plaintext exactly once - show them to the user, then discard.
 */
export const TwoFactorEnableView = Schema.Struct({
  secret: Schema.String,
  totpUri: Schema.String,
  backupCodes: Schema.Array(Schema.String),
});
export type TwoFactorEnableView = typeof TwoFactorEnableView.Type;

/** Freshly regenerated plaintext backup codes (shown once). */
export const BackupCodesView = Schema.Struct({
  backupCodes: Schema.Array(Schema.String),
});
export type BackupCodesView = typeof BackupCodesView.Type;

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

/** 404 — resource or optional feature not available (e.g. plugin not enabled). */
export class NotFound extends Schema.TaggedErrorClass<NotFound>()("NotFound", {
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
export const NotFoundError = NotFound.pipe(HttpApiSchema.status(404));
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
