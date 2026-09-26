import { Schema } from "effect";
import { HttpApiSchema } from "effect/unstable/httpapi";
import { Forbidden, Unauthorized } from "../Guard.ts";
import * as Identifier from "../Identifier.ts";
import type * as Types from "../Types.ts";

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

/** Public view of a login-handle identifier (timestamps as epoch millis). */
export const IdentifierView = Schema.Struct({
  id: Schema.String,
  type: Schema.Literals(["email", "username", "phone"]),
  value: Schema.String,
  verified: Schema.Boolean,
  verifiedAt: Schema.optional(Schema.Number),
  createdAt: Schema.Number,
});
export type IdentifierView = typeof IdentifierView.Type;

/** The authenticated user's identifiers (`GET /identifiers`). */
export const IdentifierListView = Schema.Array(IdentifierView);
export type IdentifierListView = typeof IdentifierListView.Type;

/**
 * Public view of a user (timestamps as epoch millis).
 *
 * Since the surrogate-key migration the `User` record carries no email;
 * `email`/`emailVerified` are derived from the user's email identifiers when
 * the responding handler has them at hand (the primary — earliest verified —
 * email identifier, falling back to the earliest unverified one). Responses
 * served from the signed session-cookie cache omit them.
 */
export const UserView = Schema.Struct({
  id: Schema.String,
  email: Schema.optional(Schema.String),
  emailVerified: Schema.optional(Schema.Boolean),
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
  /**
   * When `false`, the response sets a browser-session cookie (no
   * `Max-Age`/`Expires`) that is cleared when the browser is closed. Omit or
   * pass `true` for a persistent cookie matching `session.expiresAt`.
   */
  rememberMe: Schema.optional(Schema.Boolean),
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
 * user must redeem a multi-factor challenge to obtain a session.
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
  /**
   * When `false`, the response sets a browser-session cookie. See
   * `SignInPayload.rememberMe` for details.
   */
  rememberMe: Schema.optional(Schema.Boolean),
});
export type UsernameSignInPayload = typeof UsernameSignInPayload.Type;

/** Request body for signing in with an email OTP. */
export const EmailOtpSignInPayload = Schema.Struct({
  email: Schema.String,
  otp: Schema.String,
});
export type EmailOtpSignInPayload = typeof EmailOtpSignInPayload.Type;

/**
 * Request body for multi-factor operations that re-verify the user's password
 * (enable, disable, regenerate backup codes).
 */
export const MultiFactorPasswordPayload = Schema.Struct({
  password: Schema.String,
});
export type MultiFactorPasswordPayload = typeof MultiFactorPasswordPayload.Type;

/** Request body for confirming multi-factor enrollment with a TOTP code. */
export const MultiFactorConfirmPayload = Schema.Struct({
  code: Schema.String,
});
export type MultiFactorConfirmPayload = typeof MultiFactorConfirmPayload.Type;

/**
 * Request body for redeeming a pending second-factor challenge: the challenge
 * `token` (from sign-in's `secondFactor`) plus a TOTP or backup `code`.
 */
export const MultiFactorVerifyPayload = Schema.Struct({
  token: Schema.String,
  code: Schema.String,
});
export type MultiFactorVerifyPayload = typeof MultiFactorVerifyPayload.Type;

/**
 * Result of enabling multi-factor. The secret and backup codes are returned in
 * plaintext exactly once - show them to the user, then discard.
 */
export const MultiFactorEnableView = Schema.Struct({
  secret: Schema.String,
  totpUri: Schema.String,
  backupCodes: Schema.Array(Schema.String),
});
export type MultiFactorEnableView = typeof MultiFactorEnableView.Type;

/** Freshly regenerated plaintext backup codes (shown once). */
export const BackupCodesView = Schema.Struct({
  backupCodes: Schema.Array(Schema.String),
});
export type BackupCodesView = typeof BackupCodesView.Type;

// -----------------------------------------------------------------------------
// Enterprise SSO
// -----------------------------------------------------------------------------

/**
 * Public view of an **OIDC** SSO connection.
 *
 * The client secret is never echoed back, and neither is the registrar's user
 * id — both are stored on the connection but neither is part of its public
 * description.
 */
export const OidcSsoProviderView = Schema.Struct({
  id: Schema.String,
  issuer: Schema.String,
  domain: Schema.String,
  protocol: Schema.Literal("oidc"),
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
export type OidcSsoProviderView = typeof OidcSsoProviderView.Type;

/**
 * Public view of a **SAML 2.0** SSO connection.
 *
 * `idpCertificates` is echoed deliberately: they are public certificates, and
 * an administrator rotating them needs to see what this connection currently
 * pins. As with the OIDC arm the registrar's user id is omitted.
 */
export const SamlSsoProviderView = Schema.Struct({
  id: Schema.String,
  domain: Schema.String,
  protocol: Schema.Literal("saml"),
  entityId: Schema.String,
  ssoUrl: Schema.String,
  idpCertificates: Schema.Array(Schema.String),
  spEntityId: Schema.String,
  acsUrl: Schema.String,
  signatureAlgorithms: Schema.optional(Schema.Array(Schema.String)),
  wantAssertionsSigned: Schema.optional(Schema.Boolean),
  wantAuthnResponseSigned: Schema.optional(Schema.Boolean),
  forceAuthn: Schema.optional(Schema.Boolean),
  organizationId: Schema.optional(Schema.String),
  createdAt: Schema.Number,
});
export type SamlSsoProviderView = typeof SamlSsoProviderView.Type;

/**
 * Public view of an SSO connection of either protocol, discriminated on
 * `protocol` exactly as the core `SsoProvider` union is.
 */
export const SsoProviderView = Schema.Union([OidcSsoProviderView, SamlSsoProviderView]);
export type SsoProviderView = typeof SsoProviderView.Type;

/** Request body for registering an **OIDC** SSO connection (admin-gated). */
export const SsoRegisterOidcPayload = Schema.Struct({
  /** Optional for backwards compatibility: OIDC is the default protocol. */
  protocol: Schema.optional(Schema.Literal("oidc")),
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
export type SsoRegisterOidcPayload = typeof SsoRegisterOidcPayload.Type;

/** Request body for registering a **SAML 2.0** SSO connection (admin-gated). */
export const SsoRegisterSamlPayload = Schema.Struct({
  protocol: Schema.Literal("saml"),
  domain: Schema.String,
  entityId: Schema.String,
  ssoUrl: Schema.String,
  idpCertificates: Schema.Array(Schema.String),
  spEntityId: Schema.String,
  acsUrl: Schema.String,
  signatureAlgorithms: Schema.optional(Schema.Array(Schema.Literals(["sha1", "sha256", "sha512"]))),
  wantAssertionsSigned: Schema.optional(Schema.Boolean),
  wantAuthnResponseSigned: Schema.optional(Schema.Boolean),
  forceAuthn: Schema.optional(Schema.Boolean),
  organizationId: Schema.optional(Schema.String),
});
export type SsoRegisterSamlPayload = typeof SsoRegisterSamlPayload.Type;

/**
 * Request body for registering an SSO connection, discriminated on `protocol`.
 * A body without `protocol` is an OIDC registration, which is what every
 * pre-SAML client sends.
 */
export const SsoRegisterPayload = Schema.Union([SsoRegisterOidcPayload, SsoRegisterSamlPayload]);
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

/**
 * The SAML assertion consumer service (ACS) POST, exactly as the IdP sends it:
 * an `application/x-www-form-urlencoded` body carrying the base64 `SAMLResponse`
 * and, for an SP-initiated flow, the `RelayState` this server minted.
 *
 * Field names are the wire names from the SAML binding, capitals and all.
 */
export const SamlAcsPayload = Schema.Struct({
  SAMLResponse: Schema.String,
  RelayState: Schema.optional(Schema.String),
}).pipe(HttpApiSchema.asFormUrlEncoded());
export type SamlAcsPayload = typeof SamlAcsPayload.Type;

/**
 * SP metadata is XML, not JSON: an `EntityDescriptor` document served as
 * `application/samlmetadata+xml` so an IdP's "import metadata by URL" flow
 * accepts it.
 */
export const SamlMetadataView = Schema.String.pipe(
  HttpApiSchema.asText({ contentType: "application/samlmetadata+xml" }),
);
export type SamlMetadataView = typeof SamlMetadataView.Type;

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
  /** Role given to members added without an explicit one. */
  defaultRole: Schema.String,
  /** Whether a matching verified domain provisions membership on SSO sign-in. */
  jitProvisioning: Schema.Boolean,
  createdAt: Schema.Number,
});
export type OrganizationView = typeof OrganizationView.Type;

/** Public view of an organization membership. */
export const MemberView = Schema.Struct({
  id: Schema.String,
  organizationId: Schema.String,
  userId: Schema.String,
  role: Schema.String,
  /** `"inactive"` members keep their row but fail every permission check. */
  status: Schema.Literals(["active", "inactive"]),
  /** The role restored on reactivation; only present while inactive. */
  previousRole: Schema.optional(Schema.String),
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
  jitProvisioning: Schema.optional(Schema.Boolean),
});
export type UpdateOrganizationPayload = typeof UpdateOrganizationPayload.Type;

/** Request body for setting the organization's default role (owner-only). */
export const SetDefaultRolePayload = Schema.Struct({
  role: Schema.String,
});
export type SetDefaultRolePayload = typeof SetDefaultRolePayload.Type;

/** Request body for inviting a member. */
export const InviteMemberPayload = Schema.Struct({
  email: Schema.String,
  role: Schema.String,
});
export type InviteMemberPayload = typeof InviteMemberPayload.Type;

/** Request body for adding a member directly (role defaults to the org's). */
export const AddMemberPayload = Schema.Struct({
  userId: Schema.String,
  role: Schema.optional(Schema.String),
});
export type AddMemberPayload = typeof AddMemberPayload.Type;

/** Request body for updating a member's role. */
export const UpdateMemberRolePayload = Schema.Struct({
  userId: Schema.String,
  role: Schema.String,
});
export type UpdateMemberRolePayload = typeof UpdateMemberRolePayload.Type;

/** Public view of a team. */
export const TeamView = Schema.Struct({
  id: Schema.String,
  organizationId: Schema.String,
  name: Schema.String,
  createdAt: Schema.Number,
  updatedAt: Schema.Number,
});
export type TeamView = typeof TeamView.Type;

/** Public view of a team membership. */
export const TeamMemberView = Schema.Struct({
  teamId: Schema.String,
  userId: Schema.String,
  createdAt: Schema.Number,
});
export type TeamMemberView = typeof TeamMemberView.Type;

export const TeamListView = Schema.Array(TeamView);
export type TeamListView = typeof TeamListView.Type;

export const TeamMemberListView = Schema.Array(TeamMemberView);
export type TeamMemberListView = typeof TeamMemberListView.Type;

/** Request body for creating a team. */
export const CreateTeamPayload = Schema.Struct({
  name: Schema.String,
});
export type CreateTeamPayload = typeof CreateTeamPayload.Type;

/** Request body for updating a team. */
export const UpdateTeamPayload = Schema.Struct({
  name: Schema.optional(Schema.String),
});
export type UpdateTeamPayload = typeof UpdateTeamPayload.Type;

/** Request body for adding a user to a team. */
export const AddTeamMemberPayload = Schema.Struct({
  userId: Schema.String,
});
export type AddTeamMemberPayload = typeof AddTeamMemberPayload.Type;

/** Public view of a custom organization role. */
export const OrgRoleView = Schema.Struct({
  organizationId: Schema.String,
  role: Schema.String,
  permissions: Schema.Array(Schema.String),
  createdAt: Schema.Number,
  updatedAt: Schema.Number,
});
export type OrgRoleView = typeof OrgRoleView.Type;

export const OrgRoleListView = Schema.Array(OrgRoleView);
export type OrgRoleListView = typeof OrgRoleListView.Type;

/** Request body for defining a custom organization role. */
export const UpsertOrgRolePayload = Schema.Struct({
  permissions: Schema.Array(Schema.String),
});
export type UpsertOrgRolePayload = typeof UpsertOrgRolePayload.Type;

/**
 * Public view of an organization's domain claim. `verificationToken` is the
 * value to publish as a DNS TXT record; it is only present for `dns` claims,
 * and only the organization's own admins ever see it.
 */
export const OrganizationDomainView = Schema.Struct({
  id: Schema.String,
  organizationId: Schema.String,
  domain: Schema.String,
  verificationState: Schema.Literals(["pending", "verified", "failed"]),
  verificationStrategy: Schema.Literals(["dns", "manual"]),
  verificationToken: Schema.optional(Schema.String),
  createdAt: Schema.Number,
  verifiedAt: Schema.optional(Schema.Number),
});
export type OrganizationDomainView = typeof OrganizationDomainView.Type;

export const OrganizationDomainListView = Schema.Array(OrganizationDomainView);
export type OrganizationDomainListView = typeof OrganizationDomainListView.Type;

/** Request body for claiming a domain (strategy defaults to `"dns"`). */
export const AddOrganizationDomainPayload = Schema.Struct({
  domain: Schema.String,
  verificationStrategy: Schema.optional(Schema.Literals(["dns", "manual"])),
});
export type AddOrganizationDomainPayload = typeof AddOrganizationDomainPayload.Type;

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
// Google One Tap
// -----------------------------------------------------------------------------

/** Response body for the nonce-generation endpoint. */
export const GoogleOneTapNonceView = Schema.Struct({
  /** The server-side nonce. Pass this to Google's One Tap library (`data-nonce`). */
  nonce: Schema.String,
});
export type GoogleOneTapNonceView = typeof GoogleOneTapNonceView.Type;

/** Request body for a Google One Tap sign-in. */
export const GoogleOneTapPayload = Schema.Struct({
  /** The One Tap `credential` (a Google-signed id_token). */
  credential: Schema.String,
  /**
   * The **unhashed** nonce returned by `GET /sign-in/google-one-tap/nonce`.
   * Must match the nonce claim embedded by Google in the id_token.
   */
  nonce: Schema.String,
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

// -----------------------------------------------------------------------------
// RFC 7591 dynamic client registration / RFC 7592 management
// -----------------------------------------------------------------------------

/**
 * RFC 7591 §2 client metadata, as posted to `POST /register` (and `PUT` to the
 * management endpoint). Members the provider does not implement (`logo_uri`,
 * `contacts`, `software_statement`, ...) are accepted and ignored rather than
 * rejected, as RFC 7591 §2 requires.
 */
export const OidcRegistrationPayload = Schema.Struct({
  redirect_uris: Schema.Array(Schema.String),
  token_endpoint_auth_method: Schema.optional(Schema.String),
  grant_types: Schema.optional(Schema.Array(Schema.String)),
  response_types: Schema.optional(Schema.Array(Schema.String)),
  client_name: Schema.optional(Schema.String),
  scope: Schema.optional(Schema.String),
});
export type OidcRegistrationPayload = typeof OidcRegistrationPayload.Type;

/**
 * RFC 7591 §3.2.1 client information response. `client_secret` and
 * `registration_access_token` are returned only by the registration call that
 * mints them — both are stored hashed and cannot be read back afterwards.
 */
export const OidcRegistrationView = Schema.Struct({
  client_id: Schema.String,
  /** Seconds since the epoch. */
  client_id_issued_at: Schema.Number,
  client_secret: Schema.optional(Schema.String),
  /** `0` = the secret does not expire (RFC 7591 §3.2.1). */
  client_secret_expires_at: Schema.optional(Schema.Number),
  client_name: Schema.String,
  redirect_uris: Schema.Array(Schema.String),
  grant_types: Schema.Array(Schema.String),
  response_types: Schema.Array(Schema.String),
  token_endpoint_auth_method: Schema.String,
  scope: Schema.String,
  registration_access_token: Schema.optional(Schema.String),
  registration_client_uri: Schema.optional(Schema.String),
});
export type OidcRegistrationView = typeof OidcRegistrationView.Type;

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
// SCIM 2.0 (RFC 7643 resources, RFC 7644 protocol)
// -----------------------------------------------------------------------------

/** Schema URN of the SCIM core `User` resource (RFC 7643 §4.1). */
export const SCIM_USER_SCHEMA = "urn:ietf:params:scim:schemas:core:2.0:User";
/** Schema URN of the SCIM core `Group` resource (RFC 7643 §4.2). */
export const SCIM_GROUP_SCHEMA = "urn:ietf:params:scim:schemas:core:2.0:Group";
/** Schema URN of the `ListResponse` envelope (RFC 7644 §3.4.2). */
export const SCIM_LIST_RESPONSE_SCHEMA = "urn:ietf:params:scim:api:messages:2.0:ListResponse";
/** Schema URN of a `PatchOp` request body (RFC 7644 §3.5.2). */
export const SCIM_PATCH_OP_SCHEMA = "urn:ietf:params:scim:api:messages:2.0:PatchOp";
/** Schema URN of an error response (RFC 7644 §3.12). */
export const SCIM_ERROR_SCHEMA = "urn:ietf:params:scim:api:messages:2.0:Error";
/** Schema URN of the `ServiceProviderConfig` resource (RFC 7643 §5). */
export const SCIM_SERVICE_PROVIDER_CONFIG_SCHEMA =
  "urn:ietf:params:scim:schemas:core:2.0:ServiceProviderConfig";
/** Schema URN of a `ResourceType` (RFC 7643 §6). */
export const SCIM_RESOURCE_TYPE_SCHEMA = "urn:ietf:params:scim:schemas:core:2.0:ResourceType";
/** Schema URN of a `Schema` resource (RFC 7643 §7). */
export const SCIM_SCHEMA_SCHEMA = "urn:ietf:params:scim:schemas:core:2.0:Schema";

/**
 * The SCIM media type (RFC 7644 §3.1). Every SCIM request and response body on
 * this API is served as `application/scim+json` rather than plain
 * `application/json`, which is what a conformance test looks for.
 */
export const SCIM_CONTENT_TYPE = "application/scim+json";

/** Mark a schema as a SCIM (`application/scim+json`) request or response body. */
export const asScimJson = HttpApiSchema.asJson({ contentType: SCIM_CONTENT_TYPE });

/** A resource's `meta` block (RFC 7643 §3.1). Timestamps are ISO-8601. */
export const ScimMetaView = Schema.Struct({
  resourceType: Schema.String,
  created: Schema.String,
  lastModified: Schema.String,
  location: Schema.String,
});
export type ScimMetaView = typeof ScimMetaView.Type;

/** One entry of the multi-valued `emails` attribute. */
export const ScimEmailView = Schema.Struct({
  value: Schema.String,
  primary: Schema.optional(Schema.Boolean),
  type: Schema.optional(Schema.String),
});
export type ScimEmailView = typeof ScimEmailView.Type;

/** A SCIM `User` resource on the wire. */
export const ScimUserView = Schema.Struct({
  schemas: Schema.Array(Schema.String),
  id: Schema.String,
  externalId: Schema.optional(Schema.String),
  userName: Schema.String,
  displayName: Schema.optional(Schema.String),
  emails: Schema.Array(ScimEmailView),
  active: Schema.Boolean,
  meta: ScimMetaView,
});
export type ScimUserView = typeof ScimUserView.Type;

/** A SCIM `Group` resource on the wire. */
export const ScimGroupView = Schema.Struct({
  schemas: Schema.Array(Schema.String),
  id: Schema.String,
  displayName: Schema.String,
  members: Schema.Array(Schema.Struct({ value: Schema.String })),
  meta: ScimMetaView,
});
export type ScimGroupView = typeof ScimGroupView.Type;

/** The `ListResponse` envelope around a page of `User` resources. */
export const ScimUserListView = Schema.Struct({
  schemas: Schema.Array(Schema.String),
  totalResults: Schema.Number,
  startIndex: Schema.Number,
  itemsPerPage: Schema.Number,
  Resources: Schema.Array(ScimUserView),
});
export type ScimUserListView = typeof ScimUserListView.Type;

/** The `ListResponse` envelope around a page of `Group` resources. */
export const ScimGroupListView = Schema.Struct({
  schemas: Schema.Array(Schema.String),
  totalResults: Schema.Number,
  startIndex: Schema.Number,
  itemsPerPage: Schema.Number,
  Resources: Schema.Array(ScimGroupView),
});
export type ScimGroupListView = typeof ScimGroupListView.Type;

/**
 * The discovery documents (`ServiceProviderConfig`, `ResourceTypes`,
 * `Schemas`) are static, deeply-nested JSON that no client writes against
 * field by field, so they travel as open records rather than being modelled
 * attribute by attribute.
 */
export const ScimDocumentView = Schema.Record(Schema.String, Schema.Unknown);
export type ScimDocumentView = typeof ScimDocumentView.Type;

/**
 * A `User` write body (`POST`/`PUT`).
 *
 * `name` is accepted because Okta always sends it and often omits
 * `displayName`; the handler folds it into a display name rather than storing
 * the sub-attributes separately.
 */
export const ScimUserPayload = Schema.Struct({
  schemas: Schema.optional(Schema.Array(Schema.String)),
  externalId: Schema.optional(Schema.String),
  userName: Schema.String,
  displayName: Schema.optional(Schema.String),
  name: Schema.optional(
    Schema.Struct({
      formatted: Schema.optional(Schema.String),
      givenName: Schema.optional(Schema.String),
      familyName: Schema.optional(Schema.String),
    }),
  ),
  emails: Schema.optional(Schema.Array(ScimEmailView)),
  active: Schema.optional(Schema.Boolean),
});
export type ScimUserPayload = typeof ScimUserPayload.Type;

/** A `Group` write body (`POST`/`PUT`). */
export const ScimGroupPayload = Schema.Struct({
  schemas: Schema.optional(Schema.Array(Schema.String)),
  externalId: Schema.optional(Schema.String),
  displayName: Schema.String,
  members: Schema.optional(
    Schema.Array(Schema.Struct({ value: Schema.String, display: Schema.optional(Schema.String) })),
  ),
});
export type ScimGroupPayload = typeof ScimGroupPayload.Type;

/**
 * An RFC 7644 §3.5.2 `PatchOp` body. `value` is `Unknown` because SCIM's patch
 * values are genuinely polymorphic — a boolean, a string, an attribute map, or
 * an array of multi-valued entries, depending on the path.
 */
export const ScimPatchPayload = Schema.Struct({
  schemas: Schema.optional(Schema.Array(Schema.String)),
  Operations: Schema.Array(
    Schema.Struct({
      op: Schema.String,
      path: Schema.optional(Schema.String),
      value: Schema.optional(Schema.Unknown),
    }),
  ),
});
export type ScimPatchPayload = typeof ScimPatchPayload.Type;

// -----------------------------------------------------------------------------
// Error schemas (mapped to HTTP status codes via HttpApiSchema.status)
// -----------------------------------------------------------------------------

/**
 * 401 — missing/invalid credentials or session; 403 — authenticated but not
 * allowed (e.g. email not verified, account locked, banned). Defined in the
 * core (`Guard.ts`), where the zero-IO guards fail with them, and re-exported
 * here so a guard's failure is the very class these endpoints encode.
 */
export { Forbidden, Unauthorized };

/** 409 — conflict (e.g. user already exists). */
export class Conflict extends Schema.TaggedError<Conflict>()("Conflict", {
  message: Schema.String,
  code: Schema.optional(Schema.String),
}) {}

/** 400 — malformed/invalid request (e.g. password policy violation, invalid input). */
export class BadRequest extends Schema.TaggedError<BadRequest>()("BadRequest", {
  message: Schema.String,
  code: Schema.optional(Schema.String),
}) {}

/** 404 — resource or optional feature not available (e.g. plugin not enabled). */
export class NotFound extends Schema.TaggedError<NotFound>()("NotFound", {
  message: Schema.String,
  code: Schema.optional(Schema.String),
}) {}

/** 429 — rate limited; retry later. */
export class TooManyRequests extends Schema.TaggedError<TooManyRequests>()("TooManyRequests", {
  message: Schema.String,
  code: Schema.optional(Schema.String),
}) {}

/** 500 — unexpected server error. */
export class InternalServerError extends Schema.TaggedError<InternalServerError>()(
  "InternalServerError",
  { message: Schema.String },
) {}

/**
 * 400 — an OAuth error response body (`{ error, error_description }`) rather
 * than this API's `{ message }` shape. RFC 7591 §3.2.2 specifies it verbatim
 * for the dynamic client registration endpoint, and generic OAuth clients
 * (MCP clients included) read `error` to decide what to do next.
 */
export class OAuthError extends Schema.TaggedError<OAuthError>()("OAuthError", {
  /** RFC 7591 §3.2.2 code, e.g. `invalid_redirect_uri`, `invalid_client_metadata`. */
  error: Schema.String,
  error_description: Schema.optional(Schema.String),
}) {}

/**
 * SCIM error bodies (RFC 7644 §3.12).
 *
 * SCIM specifies the failure body exactly — `schemas`, a **string** `status`,
 * an optional `scimType` detail code and a human-readable `detail` — and
 * conformance suites check it, so these are `Schema.Error` rather than the
 * repo's usual `Schema.TaggedError`: a `_tag` discriminator would be an
 * extra member in a body that is meant to be verbatim.
 *
 * The `status` literal takes the discriminator's place. Effect encodes an
 * endpoint's failures as a union of its error schemas, and since exactly one
 * arm's `status` literal can match a given value, the right status code is
 * always chosen.
 */
export class ScimBadRequest extends Schema.Error<ScimBadRequest>("ScimBadRequest")({
  schemas: Schema.Array(Schema.String),
  status: Schema.Literal("400"),
  /** RFC 7644 §3.12 code: `invalidFilter`, `invalidPath`, `invalidValue`, … */
  scimType: Schema.optional(Schema.String),
  detail: Schema.optional(Schema.String),
}) {}

/** 401 — missing or unknown provisioning token. */
export class ScimUnauthorized extends Schema.Error<ScimUnauthorized>("ScimUnauthorized")({
  schemas: Schema.Array(Schema.String),
  status: Schema.Literal("401"),
  scimType: Schema.optional(Schema.String),
  detail: Schema.optional(Schema.String),
}) {}

/** 404 — no such resource, or one outside the connection's organization. */
export class ScimNotFound extends Schema.Error<ScimNotFound>("ScimNotFound")({
  schemas: Schema.Array(Schema.String),
  status: Schema.Literal("404"),
  scimType: Schema.optional(Schema.String),
  detail: Schema.optional(Schema.String),
}) {}

/** 409 — the `uniqueness` conflict an IdP reconciles against. */
export class ScimConflict extends Schema.Error<ScimConflict>("ScimConflict")({
  schemas: Schema.Array(Schema.String),
  status: Schema.Literal("409"),
  scimType: Schema.optional(Schema.String),
  detail: Schema.optional(Schema.String),
}) {}

/** 500 — unexpected server error, in SCIM's shape. */
export class ScimInternalError extends Schema.Error<ScimInternalError>("ScimInternalError")({
  schemas: Schema.Array(Schema.String),
  status: Schema.Literal("500"),
  scimType: Schema.optional(Schema.String),
  detail: Schema.optional(Schema.String),
}) {}

/** Each error class paired with its HTTP status for use in endpoint `error` fields. */
export const UnauthorizedError = Unauthorized.pipe(HttpApiSchema.status(401));
export const ForbiddenError = Forbidden.pipe(HttpApiSchema.status(403));
export const ConflictError = Conflict.pipe(HttpApiSchema.status(409));
export const BadRequestError = BadRequest.pipe(HttpApiSchema.status(400));
export const NotFoundError = NotFound.pipe(HttpApiSchema.status(404));
export const TooManyRequestsError = TooManyRequests.pipe(HttpApiSchema.status(429));
export const InternalError = InternalServerError.pipe(HttpApiSchema.status(500));
/** 400 with an RFC 7591 §3.2.2 `{ error, error_description }` body. */
export const OAuthBadRequestError = OAuthError.pipe(HttpApiSchema.status(400));

/** The SCIM error bodies, each carrying its status and the SCIM media type. */
export const ScimBadRequestError = ScimBadRequest.pipe(HttpApiSchema.status(400), asScimJson);
export const ScimUnauthorizedError = ScimUnauthorized.pipe(HttpApiSchema.status(401), asScimJson);
export const ScimNotFoundError = ScimNotFound.pipe(HttpApiSchema.status(404), asScimJson);
export const ScimConflictError = ScimConflict.pipe(HttpApiSchema.status(409), asScimJson);
export const ScimInternalServerError = ScimInternalError.pipe(
  HttpApiSchema.status(500),
  asScimJson,
);

/**
 * Every SCIM endpoint answers with the same failure set: 400 for a body or
 * filter it cannot act on, 401 for a bad token, 404 for a resource outside the
 * connection's organization (or absent entirely), 409 for a uniqueness clash,
 * and 500 for anything unexpected.
 */
export const ScimErrors = [
  ScimBadRequestError,
  ScimUnauthorizedError,
  ScimNotFoundError,
  ScimConflictError,
  ScimInternalServerError,
] as const;

// -----------------------------------------------------------------------------
// Encoders: domain types -> wire views
// -----------------------------------------------------------------------------

/**
 * Encode a user for the wire. When the caller has the user's identifiers at
 * hand, the derived `email`/`emailVerified` convenience fields are populated
 * from the email-of-record (primary verified email, else earliest email);
 * without identifiers both fields are omitted.
 */
export const encodeUser = (
  user: Types.User,
  identifiers?: ReadonlyArray<Identifier.Identifier>,
): UserView => {
  const email = identifiers === undefined ? null : Identifier.anyEmail(identifiers);
  return {
    id: user.id,
    ...(email !== null && { email: email.value, emailVerified: email.verified }),
    ...(user.name !== undefined && { name: user.name }),
    ...(user.image !== undefined && { image: user.image }),
    createdAt: user.createdAt.getTime(),
    updatedAt: user.updatedAt.getTime(),
    attributes: user.attributes,
  };
};

/** Encode an identifier for the wire (timestamps to epoch millis). */
export const encodeIdentifier = (identifier: Identifier.Identifier): IdentifierView => ({
  id: identifier.id,
  type: identifier.type,
  value: identifier.value,
  verified: identifier.verified,
  ...(identifier.verifiedAt !== undefined && { verifiedAt: identifier.verifiedAt.getTime() }),
  createdAt: identifier.createdAt.getTime(),
});

export const encodeSession = (session: Types.Session): SessionView => ({
  id: session.id,
  userId: session.userId,
  expiresAt: session.expiresAt.getTime(),
  createdAt: session.createdAt.getTime(),
  lastActivityAt: session.lastActivityAt.getTime(),
  attributes: session.attributes,
});

export const encodeSessionWithUser = (
  value: Types.SessionWithUser,
  identifiers?: ReadonlyArray<Identifier.Identifier>,
): SessionWithUserView => ({
  session: encodeSession(value.session),
  user: encodeUser(value.user, identifiers),
});
