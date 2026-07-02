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
  /** Optional captcha token consumed by the `CaptchaPlugin`. */
  captchaToken: Schema.optional(Schema.String),
});
export type SignUpPayload = typeof SignUpPayload.Type;

/** Request body for sign-in. */
export const SignInPayload = Schema.Struct({
  email: Schema.String,
  password: Schema.String,
  /** Optional captcha token consumed by the `CaptchaPlugin`. */
  captchaToken: Schema.optional(Schema.String),
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

/** List of a device's valid sessions (multi-session). */
export const MultiSessionListView = Schema.Array(SessionWithUserView);
export type MultiSessionListView = typeof MultiSessionListView.Type;

/** Request body for multi-session set-active / revoke. */
export const MultiSessionActionPayload = Schema.Struct({
  sessionId: Schema.String,
});
export type MultiSessionActionPayload = typeof MultiSessionActionPayload.Type;

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
// Enterprise SSO
// -----------------------------------------------------------------------------

/** Public view of an SSO connection (never exposes the client secret). */
export const SsoProviderView = Schema.Struct({
  id: Schema.String,
  issuer: Schema.String,
  domain: Schema.String,
  protocol: Schema.Literals(["oidc"]),
  clientId: Schema.String,
  redirectUri: Schema.String,
  authorizationEndpoint: Schema.String,
  tokenEndpoint: Schema.String,
  userInfoEndpoint: Schema.optional(Schema.String),
  jwksEndpoint: Schema.optional(Schema.String),
  scopes: Schema.Array(Schema.String),
  organizationId: Schema.optional(Schema.String),
  createdAt: Schema.Number,
});
export type SsoProviderView = typeof SsoProviderView.Type;

/** Request body for registering an SSO connection (admin-gated). */
export const SsoRegisterPayload = Schema.Struct({
  issuer: Schema.String,
  domain: Schema.String,
  clientId: Schema.String,
  clientSecret: Schema.String,
  redirectUri: Schema.String,
  discover: Schema.optional(Schema.Boolean),
  authorizationEndpoint: Schema.optional(Schema.String),
  tokenEndpoint: Schema.optional(Schema.String),
  userInfoEndpoint: Schema.optional(Schema.String),
  jwksEndpoint: Schema.optional(Schema.String),
  scopes: Schema.optional(Schema.Array(Schema.String)),
  usePKCE: Schema.optional(Schema.Boolean),
  organizationId: Schema.optional(Schema.String),
});
export type SsoRegisterPayload = typeof SsoRegisterPayload.Type;

/** Request body for starting an SSO sign-in (any one of the fields). */
export const SsoSignInPayload = Schema.Struct({
  email: Schema.optional(Schema.String),
  domain: Schema.optional(Schema.String),
  providerId: Schema.optional(Schema.String),
});
export type SsoSignInPayload = typeof SsoSignInPayload.Type;

/** The IdP authorization URL to redirect the user to, with its CSRF state. */
export const SsoUrlView = Schema.Struct({
  url: Schema.String,
  state: Schema.String,
});
export type SsoUrlView = typeof SsoUrlView.Type;

/** Request body for completing an SSO callback. */
export const SsoCallbackPayload = Schema.Struct({
  state: Schema.String,
  code: Schema.String,
});
export type SsoCallbackPayload = typeof SsoCallbackPayload.Type;

// -----------------------------------------------------------------------------
// Organization
// -----------------------------------------------------------------------------

/** Public view of an organization. */
export const OrganizationView = Schema.Struct({
  id: Schema.String,
  name: Schema.String,
  slug: Schema.String,
  logo: Schema.optional(Schema.String),
  metadata: Attributes,
  createdAt: Schema.Number,
});
export type OrganizationView = typeof OrganizationView.Type;

/** Public view of an organization membership. */
export const MemberView = Schema.Struct({
  id: Schema.String,
  organizationId: Schema.String,
  userId: Schema.String,
  role: Schema.String,
  createdAt: Schema.Number,
});
export type MemberView = typeof MemberView.Type;

/** Public view of an invitation. */
export const InvitationView = Schema.Struct({
  id: Schema.String,
  organizationId: Schema.String,
  email: Schema.String,
  role: Schema.String,
  status: Schema.Literals(["pending", "accepted", "rejected", "canceled"]),
  inviterId: Schema.String,
  expiresAt: Schema.Number,
  createdAt: Schema.Number,
});
export type InvitationView = typeof InvitationView.Type;

/** An organization together with its members. */
export const FullOrganizationView = Schema.Struct({
  organization: OrganizationView,
  members: Schema.Array(MemberView),
});
export type FullOrganizationView = typeof FullOrganizationView.Type;

export const OrganizationListView = Schema.Array(OrganizationView);
export type OrganizationListView = typeof OrganizationListView.Type;

export const InvitationListView = Schema.Array(InvitationView);
export type InvitationListView = typeof InvitationListView.Type;

/** Request body for creating an organization. */
export const CreateOrganizationPayload = Schema.Struct({
  name: Schema.String,
  slug: Schema.String,
  logo: Schema.optional(Schema.String),
  metadata: Schema.optional(Attributes),
});
export type CreateOrganizationPayload = typeof CreateOrganizationPayload.Type;

/** Request body for updating an organization. */
export const UpdateOrganizationPayload = Schema.Struct({
  name: Schema.optional(Schema.String),
  slug: Schema.optional(Schema.String),
  logo: Schema.optional(Schema.String),
  metadata: Schema.optional(Attributes),
});
export type UpdateOrganizationPayload = typeof UpdateOrganizationPayload.Type;

/** Request body for inviting a member. */
export const InviteMemberPayload = Schema.Struct({
  email: Schema.String,
  role: Schema.String,
});
export type InviteMemberPayload = typeof InviteMemberPayload.Type;

/** Request body for adding a member directly. */
export const AddMemberPayload = Schema.Struct({
  userId: Schema.String,
  role: Schema.String,
});
export type AddMemberPayload = typeof AddMemberPayload.Type;

/** Request body for updating a member's role. */
export const UpdateMemberRolePayload = Schema.Struct({
  userId: Schema.String,
  role: Schema.String,
});
export type UpdateMemberRolePayload = typeof UpdateMemberRolePayload.Type;

/** Request body for setting the session's active organization (null clears it). */
export const SetActiveOrganizationPayload = Schema.Struct({
  organizationId: Schema.NullOr(Schema.String),
});
export type SetActiveOrganizationPayload = typeof SetActiveOrganizationPayload.Type;

// -----------------------------------------------------------------------------
// Admin
// -----------------------------------------------------------------------------

/** Paginated user listing (admin). */
export const AdminUserListView = Schema.Struct({
  users: Schema.Array(UserView),
  total: Schema.Number,
});
export type AdminUserListView = typeof AdminUserListView.Type;

/** Request body for listing users (admin). */
export const AdminListUsersPayload = Schema.Struct({
  limit: Schema.optional(Schema.Number),
  offset: Schema.optional(Schema.Number),
  searchEmail: Schema.optional(Schema.String),
});
export type AdminListUsersPayload = typeof AdminListUsersPayload.Type;

/** Request body for setting a user's role (admin). */
export const AdminSetRolePayload = Schema.Struct({
  userId: Schema.String,
  role: Schema.String,
});
export type AdminSetRolePayload = typeof AdminSetRolePayload.Type;

/** Request body for banning a user (admin). */
export const AdminBanUserPayload = Schema.Struct({
  userId: Schema.String,
  reason: Schema.optional(Schema.String),
  expiresIn: Schema.optional(Schema.Number),
});
export type AdminBanUserPayload = typeof AdminBanUserPayload.Type;

/** Request body identifying a target user (admin). */
export const AdminUserActionPayload = Schema.Struct({
  userId: Schema.String,
});
export type AdminUserActionPayload = typeof AdminUserActionPayload.Type;

// -----------------------------------------------------------------------------
// API keys
// -----------------------------------------------------------------------------

/** Per-key rate-limit configuration. */
export const ApiKeyRateLimit = Schema.Struct({
  maxRequests: Schema.Number,
  windowMs: Schema.Number,
});

/** Public view of an API key (never includes the plaintext or hash). */
export const ApiKeyView = Schema.Struct({
  id: Schema.String,
  name: Schema.optional(Schema.String),
  prefix: Schema.optional(Schema.String),
  start: Schema.String,
  userId: Schema.String,
  enabled: Schema.Boolean,
  expiresAt: Schema.optional(Schema.Number),
  lastUsedAt: Schema.optional(Schema.Number),
  permissions: Schema.optional(Schema.Record(Schema.String, Schema.Array(Schema.String))),
  metadata: Attributes,
  remaining: Schema.optional(Schema.Number),
  rateLimit: Schema.optional(ApiKeyRateLimit),
  createdAt: Schema.Number,
  updatedAt: Schema.Number,
});
export type ApiKeyView = typeof ApiKeyView.Type;

/** Result of creating an API key: the plaintext key (shown once) + its record. */
export const ApiKeyCreatedView = Schema.Struct({
  key: Schema.String,
  apiKey: ApiKeyView,
});
export type ApiKeyCreatedView = typeof ApiKeyCreatedView.Type;

export const ApiKeyListView = Schema.Array(ApiKeyView);
export type ApiKeyListView = typeof ApiKeyListView.Type;

/** Request body for creating an API key. */
export const ApiKeyCreatePayload = Schema.Struct({
  name: Schema.optional(Schema.String),
  prefix: Schema.optional(Schema.String),
  expiresIn: Schema.optional(Schema.Number),
  permissions: Schema.optional(Schema.Record(Schema.String, Schema.Array(Schema.String))),
  metadata: Schema.optional(Attributes),
  remaining: Schema.optional(Schema.Number),
  rateLimit: Schema.optional(ApiKeyRateLimit),
});
export type ApiKeyCreatePayload = typeof ApiKeyCreatePayload.Type;

/** Request body for updating an API key. */
export const ApiKeyUpdatePayload = Schema.Struct({
  name: Schema.optional(Schema.String),
  enabled: Schema.optional(Schema.Boolean),
  expiresAt: Schema.optional(Schema.Number),
  permissions: Schema.optional(Schema.Record(Schema.String, Schema.Array(Schema.String))),
  metadata: Schema.optional(Attributes),
  remaining: Schema.optional(Schema.Number),
  rateLimit: Schema.optional(ApiKeyRateLimit),
});
export type ApiKeyUpdatePayload = typeof ApiKeyUpdatePayload.Type;

// -----------------------------------------------------------------------------
// SIWE (Sign-In With Ethereum) + Google One Tap
// -----------------------------------------------------------------------------

/** A single-use SIWE nonce and its expiry (epoch millis). */
export const SiweNonceView = Schema.Struct({
  nonce: Schema.String,
  expiresAt: Schema.Number,
});
export type SiweNonceView = typeof SiweNonceView.Type;

/** Request body for completing a SIWE sign-in. */
export const SiweVerifyPayload = Schema.Struct({
  /** The signed EIP-4361 plaintext message. */
  message: Schema.String,
  /** 65-byte `r || s || v` signature, `0x`-prefixed hex. */
  signature: Schema.String,
});
export type SiweVerifyPayload = typeof SiweVerifyPayload.Type;

/** Request body for a Google One Tap sign-in. */
export const GoogleOneTapPayload = Schema.Struct({
  /** The One Tap `credential` (a Google-signed id_token). */
  credential: Schema.String,
});
export type GoogleOneTapPayload = typeof GoogleOneTapPayload.Type;

// -----------------------------------------------------------------------------
// OIDC provider (this server acting as an OpenID Connect IdP)
// -----------------------------------------------------------------------------

/** Public view of a registered OIDC client (never exposes the secret hash). */
export const OidcClientView = Schema.Struct({
  clientId: Schema.String,
  name: Schema.String,
  redirectUris: Schema.Array(Schema.String),
  type: Schema.Literals(["web", "native"]),
  skipConsent: Schema.Boolean,
  disabled: Schema.Boolean,
  metadata: Attributes,
  createdAt: Schema.Number,
  updatedAt: Schema.Number,
});
export type OidcClientView = typeof OidcClientView.Type;

/** Result of registering a client: the plaintext secret is shown exactly once. */
export const OidcClientCreatedView = Schema.Struct({
  client: OidcClientView,
  clientSecret: Schema.optional(Schema.String),
});
export type OidcClientCreatedView = typeof OidcClientCreatedView.Type;

export const OidcClientListView = Schema.Array(OidcClientView);
export type OidcClientListView = typeof OidcClientListView.Type;

/** Request body for registering an OIDC client (admin-gated). */
export const OidcRegisterClientPayload = Schema.Struct({
  name: Schema.String,
  redirectUris: Schema.Array(Schema.String),
  type: Schema.optional(Schema.Literals(["web", "native"])),
  skipConsent: Schema.optional(Schema.Boolean),
  metadata: Schema.optional(Attributes),
});
export type OidcRegisterClientPayload = typeof OidcRegisterClientPayload.Type;

/** Request body for updating an OIDC client (admin-gated). */
export const OidcClientUpdatePayload = Schema.Struct({
  name: Schema.optional(Schema.String),
  redirectUris: Schema.optional(Schema.Array(Schema.String)),
  skipConsent: Schema.optional(Schema.Boolean),
  disabled: Schema.optional(Schema.Boolean),
  metadata: Schema.optional(Attributes),
});
export type OidcClientUpdatePayload = typeof OidcClientUpdatePayload.Type;

/** Request body for resolving a pending consent request. */
export const OidcConsentPayload = Schema.Struct({
  consentCode: Schema.String,
  accept: Schema.Boolean,
});
export type OidcConsentPayload = typeof OidcConsentPayload.Type;

/** Where to send the user after a consent decision. */
export const OidcRedirectView = Schema.Struct({
  redirectTo: Schema.String,
});
export type OidcRedirectView = typeof OidcRedirectView.Type;

/**
 * Token endpoint request (RFC 6749 snake_case). Accepted as JSON or
 * `application/x-www-form-urlencoded`; client credentials may instead come
 * from a Basic Authorization header.
 */
export const OidcTokenPayload = Schema.Struct({
  grant_type: Schema.String,
  code: Schema.optional(Schema.String),
  redirect_uri: Schema.optional(Schema.String),
  code_verifier: Schema.optional(Schema.String),
  refresh_token: Schema.optional(Schema.String),
  client_id: Schema.optional(Schema.String),
  client_secret: Schema.optional(Schema.String),
  scope: Schema.optional(Schema.String),
});
export type OidcTokenPayload = typeof OidcTokenPayload.Type;

/** Token endpoint success response (RFC 6749 snake_case). */
export const OidcTokenView = Schema.Struct({
  access_token: Schema.String,
  token_type: Schema.String,
  expires_in: Schema.Number,
  refresh_token: Schema.optional(Schema.String),
  id_token: Schema.optional(Schema.String),
  scope: Schema.String,
});
export type OidcTokenView = typeof OidcTokenView.Type;

/** UserInfo response / OpenID Provider Metadata: open-ended claim records. */
export const ClaimsView = Schema.Record(Schema.String, Schema.Unknown);
export type ClaimsView = typeof ClaimsView.Type;

// -----------------------------------------------------------------------------
// JWT
// -----------------------------------------------------------------------------

/** A minted JWT plus its expiry (epoch millis). */
export const JwtTokenView = Schema.Struct({
  token: Schema.String,
  expiresAt: Schema.Number,
});
export type JwtTokenView = typeof JwtTokenView.Type;

/** A JWKS document (opaque key objects). */
export const JwksView = Schema.Struct({
  keys: Schema.Array(Schema.Record(Schema.String, Schema.Unknown)),
});
export type JwksView = typeof JwksView.Type;

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
