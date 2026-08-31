import { Schema } from "effect";
import {
  HttpApi,
  HttpApiEndpoint,
  HttpApiGroup,
  HttpApiSchema,
  OpenApi,
} from "effect/unstable/httpapi";
import * as S from "./HttpApiSchema.ts";

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
    error: [
      S.ConflictError,
      S.BadRequestError,
      S.ForbiddenError,
      S.InternalError,
      S.TooManyRequestsError,
    ],
  }),
  HttpApiEndpoint.post("signIn", "/sign-in", {
    payload: S.SignInPayload,
    success: S.AuthSuccess,
    error: [
      S.UnauthorizedError,
      S.ForbiddenError,
      S.BadRequestError,
      S.InternalError,
      S.TooManyRequestsError,
    ],
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
    error: [S.BadRequestError, S.ForbiddenError, S.InternalError, S.TooManyRequestsError],
  }),
  HttpApiEndpoint.post("verifyEmail", "/email-verification/verify", {
    payload: S.VerifyEmailPayload,
    success: S.AuthSuccess,
    error: [S.BadRequestError, S.ForbiddenError, S.InternalError, S.TooManyRequestsError],
  }),
  HttpApiEndpoint.post("passwordResetRequest", "/password-reset/request", {
    payload: S.RequestPasswordResetPayload,
    success: S.StatusResponse,
    error: [S.BadRequestError, S.ForbiddenError, S.InternalError, S.TooManyRequestsError],
  }),
  HttpApiEndpoint.post("passwordResetConfirm", "/password-reset/reset", {
    payload: S.ResetPasswordPayload,
    success: S.StatusResponse,
    error: [S.BadRequestError, S.ForbiddenError, S.InternalError, S.TooManyRequestsError],
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
  // Login-handle identifiers (email/username/phone) of the signed-in user.
  HttpApiEndpoint.get("listIdentifiers", "/identifiers", {
    success: S.IdentifierListView,
    error: [S.UnauthorizedError, S.InternalError],
  }),
  HttpApiEndpoint.delete("deleteIdentifier", "/identifiers/:identifierId", {
    params: { identifierId: Schema.String },
    success: HttpApiSchema.NoContent,
    error: [S.UnauthorizedError, S.BadRequestError, S.InternalError],
  }),
  HttpApiEndpoint.post("revokeOtherSessions", "/sessions/revoke-others", {
    success: HttpApiSchema.NoContent,
    error: [S.UnauthorizedError, S.InternalError],
  }),
  // --- Optional features (magic link / email OTP / multi-factor). Each fails
  // --- with 404 NotFound when the corresponding service layer is absent.
  // Anti-enumeration: always `{ status: true }`; 500 only on store/delivery failure.
  HttpApiEndpoint.post("magicLinkSend", "/magic-link/send", {
    payload: S.MagicLinkSendPayload,
    success: S.StatusResponse,
    error: [S.NotFoundError, S.TooManyRequestsError, S.InternalError],
  }),
  // Invalid/expired/replayed magic link tokens -> 400 BadRequest.
  HttpApiEndpoint.post("magicLinkVerify", "/magic-link/verify", {
    payload: S.MagicLinkVerifyPayload,
    success: S.AuthSuccess,
    error: [
      S.NotFoundError,
      S.BadRequestError,
      S.ForbiddenError,
      S.InternalError,
      S.TooManyRequestsError,
    ],
  }),
  // Account management: verification-gated email change & self-service deletion.
  // Request endpoints are session-authenticated; confirm endpoints are by token.
  // Anti-enumeration: request endpoints always answer `{ status: true }`.
  HttpApiEndpoint.post("changeEmailRequest", "/change-email/request", {
    payload: S.ChangeEmailRequestPayload,
    success: S.StatusResponse,
    error: [S.NotFoundError, S.UnauthorizedError, S.InternalError],
  }),
  HttpApiEndpoint.post("changeEmailConfirm", "/change-email/confirm", {
    payload: S.ChangeEmailConfirmPayload,
    success: S.StatusResponse,
    error: [S.NotFoundError, S.BadRequestError, S.InternalError],
  }),
  HttpApiEndpoint.post("deleteUserRequest", "/delete-user/request", {
    success: S.StatusResponse,
    error: [S.NotFoundError, S.UnauthorizedError, S.InternalError],
  }),
  HttpApiEndpoint.post("deleteUserConfirm", "/delete-user/confirm", {
    payload: S.DeleteUserConfirmPayload,
    success: S.StatusResponse,
    error: [S.NotFoundError, S.BadRequestError, S.InternalError],
  }),
  // Anti-enumeration: always `{ status: true }`; 500 only on store/delivery failure.
  HttpApiEndpoint.post("emailOTPSend", "/email-otp/send", {
    payload: S.EmailOTPSendPayload,
    success: S.StatusResponse,
    error: [S.NotFoundError, S.TooManyRequestsError, S.InternalError],
  }),
  // Invalid/expired OTPs and exhausted attempts -> 400 BadRequest.
  HttpApiEndpoint.post("signInEmailOTP", "/sign-in/email-otp", {
    payload: S.EmailOTPSignInPayload,
    success: S.AuthSuccess,
    error: [
      S.NotFoundError,
      S.BadRequestError,
      S.ForbiddenError,
      S.InternalError,
      S.TooManyRequestsError,
    ],
  }),
  // Guest sign-in: creates an anonymous user + session. 404 when unconfigured.
  HttpApiEndpoint.post("signInAnonymous", "/sign-in/anonymous", {
    success: S.AuthSuccess,
    error: [
      S.NotFoundError,
      S.ForbiddenError,
      S.BadRequestError,
      S.InternalError,
      S.TooManyRequestsError,
    ],
  }),
  // Username + password sign-in. Invalid credentials -> 401 (uniform message).
  HttpApiEndpoint.post("signInUsername", "/sign-in/username", {
    payload: S.UsernameSignInPayload,
    success: S.AuthSuccess,
    error: [
      S.NotFoundError,
      S.UnauthorizedError,
      S.ForbiddenError,
      S.BadRequestError,
      S.InternalError,
      S.TooManyRequestsError,
    ],
  }),
  // Multi-session (several accounts per device). 404 when not enabled.
  HttpApiEndpoint.get("multiSessionList", "/multi-session/list", {
    success: S.MultiSessionListView,
    error: [S.NotFoundError, S.InternalError],
  }),
  HttpApiEndpoint.post("multiSessionSetActive", "/multi-session/set-active", {
    payload: S.MultiSessionActionPayload,
    success: S.StatusResponse,
    error: [S.NotFoundError, S.BadRequestError, S.InternalError],
  }),
  HttpApiEndpoint.post("multiSessionRevoke", "/multi-session/revoke", {
    payload: S.MultiSessionActionPayload,
    success: S.StatusResponse,
    error: [S.NotFoundError, S.InternalError],
  }),
  // Device authorization grant (RFC 8628). 404 when unconfigured.
  HttpApiEndpoint.post("deviceCode", "/device/code", {
    payload: S.DeviceCodePayload,
    success: S.DeviceCodeView,
    error: [S.NotFoundError, S.InternalError],
  }),
  // Poll: RFC error codes (authorization_pending/slow_down/...) -> 400.
  HttpApiEndpoint.post("deviceToken", "/device/token", {
    payload: S.DeviceTokenPayload,
    success: S.AuthSuccess,
    error: [
      S.NotFoundError,
      S.BadRequestError,
      S.ForbiddenError,
      S.InternalError,
      S.TooManyRequestsError,
    ],
  }),
  HttpApiEndpoint.post("deviceApprove", "/device/approve", {
    payload: S.DeviceUserCodePayload,
    success: S.StatusResponse,
    error: [
      S.NotFoundError,
      S.UnauthorizedError,
      S.BadRequestError,
      S.TooManyRequestsError,
      S.InternalError,
    ],
  }),
  HttpApiEndpoint.post("deviceDeny", "/device/deny", {
    payload: S.DeviceUserCodePayload,
    success: S.StatusResponse,
    error: [S.NotFoundError, S.BadRequestError, S.TooManyRequestsError, S.InternalError],
  }),
  // Phone (SMS) OTP. Anti-enumeration: send always answers `{ status: true }`.
  HttpApiEndpoint.post("phoneOTPSend", "/phone-otp/send", {
    payload: S.PhoneOTPSendPayload,
    success: S.StatusResponse,
    error: [S.NotFoundError, S.TooManyRequestsError, S.InternalError],
  }),
  HttpApiEndpoint.post("signInPhoneOTP", "/sign-in/phone-otp", {
    payload: S.PhoneOTPSignInPayload,
    success: S.AuthSuccess,
    error: [
      S.NotFoundError,
      S.BadRequestError,
      S.ForbiddenError,
      S.InternalError,
      S.TooManyRequestsError,
    ],
  }),
  // Authenticated; wrong password -> 400 BadRequest (mirrors change-password).
  HttpApiEndpoint.post("multiFactorEnable", "/multi-factor/enable", {
    payload: S.MultiFactorPasswordPayload,
    success: S.MultiFactorEnableView,
    error: [S.NotFoundError, S.UnauthorizedError, S.BadRequestError, S.InternalError],
  }),
  // Authenticated; invalid TOTP code or no pending enrollment -> 400 BadRequest.
  HttpApiEndpoint.post("multiFactorConfirm", "/multi-factor/confirm", {
    payload: S.MultiFactorConfirmPayload,
    success: S.StatusResponse,
    error: [S.NotFoundError, S.UnauthorizedError, S.BadRequestError, S.InternalError],
  }),
  // Authenticated; wrong password -> 400 BadRequest.
  HttpApiEndpoint.post("multiFactorDisable", "/multi-factor/disable", {
    payload: S.MultiFactorPasswordPayload,
    success: S.StatusResponse,
    error: [S.NotFoundError, S.UnauthorizedError, S.BadRequestError, S.InternalError],
  }),
  // Authenticated; wrong password or multi-factor not enabled -> 400 BadRequest.
  HttpApiEndpoint.post(
    "multiFactorRegenerateBackupCodes",
    "/multi-factor/regenerate-backup-codes",
    {
      payload: S.MultiFactorPasswordPayload,
      success: S.BackupCodesView,
      error: [S.NotFoundError, S.UnauthorizedError, S.BadRequestError, S.InternalError],
    },
  ),
  // Failed second factor (bad/expired challenge token or wrong code) -> 401
  // Unauthorized: redeeming a challenge is an authentication attempt.
  HttpApiEndpoint.post("multiFactorVerifyTotp", "/multi-factor/verify-totp", {
    payload: S.MultiFactorVerifyPayload,
    success: S.AuthSuccess,
    error: [
      S.NotFoundError,
      S.UnauthorizedError,
      S.ForbiddenError,
      S.BadRequestError,
      S.InternalError,
      S.TooManyRequestsError,
    ],
  }),
  // Same convention as verify-totp; backup codes are single-use.
  HttpApiEndpoint.post("multiFactorVerifyBackupCode", "/multi-factor/verify-backup-code", {
    payload: S.MultiFactorVerifyPayload,
    success: S.AuthSuccess,
    error: [
      S.NotFoundError,
      S.UnauthorizedError,
      S.ForbiddenError,
      S.BadRequestError,
      S.InternalError,
      S.TooManyRequestsError,
    ],
  }),
  // --- Organization (session-authenticated). 404 when the module is absent;
  // --- 403 when the actor's role lacks the required permission.
  HttpApiEndpoint.post("orgCreate", "/organization/create", {
    payload: S.CreateOrganizationPayload,
    success: S.OrganizationView,
    error: [
      S.NotFoundError,
      S.UnauthorizedError,
      S.ForbiddenError,
      S.BadRequestError,
      S.InternalError,
    ],
  }),
  HttpApiEndpoint.get("orgList", "/organizations", {
    success: S.OrganizationListView,
    error: [S.NotFoundError, S.UnauthorizedError, S.InternalError],
  }),
  HttpApiEndpoint.get("orgGet", "/organization/:organizationId", {
    params: { organizationId: Schema.String },
    success: S.FullOrganizationView,
    error: [S.NotFoundError, S.UnauthorizedError, S.BadRequestError, S.InternalError],
  }),
  HttpApiEndpoint.patch("orgUpdate", "/organization/:organizationId", {
    params: { organizationId: Schema.String },
    payload: S.UpdateOrganizationPayload,
    success: S.OrganizationView,
    error: [
      S.NotFoundError,
      S.UnauthorizedError,
      S.ForbiddenError,
      S.BadRequestError,
      S.InternalError,
    ],
  }),
  HttpApiEndpoint.delete("orgDelete", "/organization/:organizationId", {
    params: { organizationId: Schema.String },
    success: HttpApiSchema.NoContent,
    error: [
      S.NotFoundError,
      S.UnauthorizedError,
      S.ForbiddenError,
      S.BadRequestError,
      S.InternalError,
    ],
  }),
  HttpApiEndpoint.post("orgSetActive", "/organization/set-active", {
    payload: S.SetActiveOrganizationPayload,
    success: S.StatusResponse,
    error: [S.NotFoundError, S.UnauthorizedError, S.InternalError],
  }),
  HttpApiEndpoint.post("orgInvite", "/organization/:organizationId/invitations", {
    params: { organizationId: Schema.String },
    payload: S.InviteMemberPayload,
    success: S.InvitationView,
    error: [
      S.NotFoundError,
      S.UnauthorizedError,
      S.ForbiddenError,
      S.BadRequestError,
      S.InternalError,
    ],
  }),
  HttpApiEndpoint.get("orgListInvitations", "/organization/:organizationId/invitations", {
    params: { organizationId: Schema.String },
    success: S.InvitationListView,
    error: [S.NotFoundError, S.UnauthorizedError, S.InternalError],
  }),
  HttpApiEndpoint.post("orgAcceptInvitation", "/invitations/:invitationId/accept", {
    params: { invitationId: Schema.String },
    success: S.MemberView,
    error: [S.NotFoundError, S.UnauthorizedError, S.BadRequestError, S.InternalError],
  }),
  HttpApiEndpoint.post("orgRejectInvitation", "/invitations/:invitationId/reject", {
    params: { invitationId: Schema.String },
    success: S.InvitationView,
    error: [S.NotFoundError, S.UnauthorizedError, S.BadRequestError, S.InternalError],
  }),
  HttpApiEndpoint.post("orgCancelInvitation", "/invitations/:invitationId/cancel", {
    params: { invitationId: Schema.String },
    success: S.InvitationView,
    error: [
      S.NotFoundError,
      S.UnauthorizedError,
      S.ForbiddenError,
      S.BadRequestError,
      S.InternalError,
    ],
  }),
  HttpApiEndpoint.post("orgAddMember", "/organization/:organizationId/members", {
    params: { organizationId: Schema.String },
    payload: S.AddMemberPayload,
    success: S.MemberView,
    error: [
      S.NotFoundError,
      S.UnauthorizedError,
      S.ForbiddenError,
      S.BadRequestError,
      S.InternalError,
    ],
  }),
  HttpApiEndpoint.patch("orgUpdateMemberRole", "/organization/:organizationId/members", {
    params: { organizationId: Schema.String },
    payload: S.UpdateMemberRolePayload,
    success: S.MemberView,
    error: [
      S.NotFoundError,
      S.UnauthorizedError,
      S.ForbiddenError,
      S.BadRequestError,
      S.InternalError,
    ],
  }),
  HttpApiEndpoint.delete("orgRemoveMember", "/organization/:organizationId/members/:userId", {
    params: { organizationId: Schema.String, userId: Schema.String },
    success: HttpApiSchema.NoContent,
    error: [
      S.NotFoundError,
      S.UnauthorizedError,
      S.ForbiddenError,
      S.BadRequestError,
      S.InternalError,
    ],
  }),
  // Dynamic access control: per-organization role definitions. Writes need the
  // `role:manage` permission (owner-only by default); any member may list.
  HttpApiEndpoint.put("orgUpsertRole", "/organization/:organizationId/roles/:role", {
    params: { organizationId: Schema.String, role: Schema.String },
    payload: S.UpsertOrgRolePayload,
    success: S.OrgRoleView,
    error: [
      S.NotFoundError,
      S.UnauthorizedError,
      S.ForbiddenError,
      S.BadRequestError,
      S.InternalError,
    ],
  }),
  HttpApiEndpoint.get("orgListRoles", "/organization/:organizationId/roles", {
    params: { organizationId: Schema.String },
    success: S.OrgRoleListView,
    error: [
      S.NotFoundError,
      S.UnauthorizedError,
      S.ForbiddenError,
      S.BadRequestError,
      S.InternalError,
    ],
  }),
  HttpApiEndpoint.delete("orgDeleteRole", "/organization/:organizationId/roles/:role", {
    params: { organizationId: Schema.String, role: Schema.String },
    success: HttpApiSchema.NoContent,
    error: [
      S.NotFoundError,
      S.UnauthorizedError,
      S.ForbiddenError,
      S.BadRequestError,
      S.InternalError,
    ],
  }),
  // Teams are organization sub-groups; the `team:*` permissions that gate them
  // are organization-scoped, so team-scoped routes resolve the organization
  // through the team id.
  HttpApiEndpoint.post("orgCreateTeam", "/organization/:organizationId/teams", {
    params: { organizationId: Schema.String },
    payload: S.CreateTeamPayload,
    success: S.TeamView,
    error: [
      S.NotFoundError,
      S.UnauthorizedError,
      S.ForbiddenError,
      S.BadRequestError,
      S.InternalError,
    ],
  }),
  HttpApiEndpoint.get("orgListTeams", "/organization/:organizationId/teams", {
    params: { organizationId: Schema.String },
    success: S.TeamListView,
    error: [
      S.NotFoundError,
      S.UnauthorizedError,
      S.ForbiddenError,
      S.BadRequestError,
      S.InternalError,
    ],
  }),
  HttpApiEndpoint.get(
    "orgListTeamsForMember",
    "/organization/:organizationId/members/:userId/teams",
    {
      params: { organizationId: Schema.String, userId: Schema.String },
      success: S.TeamListView,
      error: [
        S.NotFoundError,
        S.UnauthorizedError,
        S.ForbiddenError,
        S.BadRequestError,
        S.InternalError,
      ],
    },
  ),
  HttpApiEndpoint.patch("orgUpdateTeam", "/teams/:teamId", {
    params: { teamId: Schema.String },
    payload: S.UpdateTeamPayload,
    success: S.TeamView,
    error: [
      S.NotFoundError,
      S.UnauthorizedError,
      S.ForbiddenError,
      S.BadRequestError,
      S.InternalError,
    ],
  }),
  HttpApiEndpoint.delete("orgDeleteTeam", "/teams/:teamId", {
    params: { teamId: Schema.String },
    success: HttpApiSchema.NoContent,
    error: [
      S.NotFoundError,
      S.UnauthorizedError,
      S.ForbiddenError,
      S.BadRequestError,
      S.InternalError,
    ],
  }),
  HttpApiEndpoint.post("orgAddTeamMember", "/teams/:teamId/members", {
    params: { teamId: Schema.String },
    payload: S.AddTeamMemberPayload,
    success: S.TeamMemberView,
    error: [
      S.NotFoundError,
      S.UnauthorizedError,
      S.ForbiddenError,
      S.BadRequestError,
      S.InternalError,
    ],
  }),
  HttpApiEndpoint.get("orgListTeamMembers", "/teams/:teamId/members", {
    params: { teamId: Schema.String },
    success: S.TeamMemberListView,
    error: [
      S.NotFoundError,
      S.UnauthorizedError,
      S.ForbiddenError,
      S.BadRequestError,
      S.InternalError,
    ],
  }),
  HttpApiEndpoint.delete("orgRemoveTeamMember", "/teams/:teamId/members/:userId", {
    params: { teamId: Schema.String, userId: Schema.String },
    success: HttpApiSchema.NoContent,
    error: [
      S.NotFoundError,
      S.UnauthorizedError,
      S.ForbiddenError,
      S.BadRequestError,
      S.InternalError,
    ],
  }),
  // --- Admin (session-authenticated; the actor must satisfy `isAdmin`).
  // --- Authorization failures answer 403.
  HttpApiEndpoint.post("adminListUsers", "/admin/users/list", {
    payload: S.AdminListUsersPayload,
    success: S.AdminUserListView,
    error: [S.NotFoundError, S.UnauthorizedError, S.ForbiddenError, S.InternalError],
  }),
  HttpApiEndpoint.post("adminSetRole", "/admin/users/set-role", {
    payload: S.AdminSetRolePayload,
    success: S.UserView,
    error: [
      S.NotFoundError,
      S.UnauthorizedError,
      S.ForbiddenError,
      S.BadRequestError,
      S.InternalError,
    ],
  }),
  HttpApiEndpoint.post("adminBanUser", "/admin/users/ban", {
    payload: S.AdminBanUserPayload,
    success: S.UserView,
    error: [
      S.NotFoundError,
      S.UnauthorizedError,
      S.ForbiddenError,
      S.BadRequestError,
      S.InternalError,
    ],
  }),
  HttpApiEndpoint.post("adminUnbanUser", "/admin/users/unban", {
    payload: S.AdminUserActionPayload,
    success: S.UserView,
    error: [
      S.NotFoundError,
      S.UnauthorizedError,
      S.ForbiddenError,
      S.BadRequestError,
      S.InternalError,
    ],
  }),
  HttpApiEndpoint.post("adminRemoveUser", "/admin/users/remove", {
    payload: S.AdminUserActionPayload,
    success: HttpApiSchema.NoContent,
    error: [S.NotFoundError, S.UnauthorizedError, S.ForbiddenError, S.InternalError],
  }),
  HttpApiEndpoint.post("adminRevokeSessions", "/admin/users/revoke-sessions", {
    payload: S.AdminUserActionPayload,
    success: S.StatusResponse,
    error: [S.NotFoundError, S.UnauthorizedError, S.ForbiddenError, S.InternalError],
  }),
  HttpApiEndpoint.post("adminImpersonate", "/admin/impersonate", {
    payload: S.AdminUserActionPayload,
    success: S.AuthSuccess,
    error: [
      S.NotFoundError,
      S.UnauthorizedError,
      S.ForbiddenError,
      S.BadRequestError,
      S.InternalError,
      S.TooManyRequestsError,
    ],
  }),
  HttpApiEndpoint.post("adminStopImpersonating", "/admin/stop-impersonating", {
    success: S.StatusResponse,
    error: [S.NotFoundError, S.UnauthorizedError, S.InternalError],
  }),
  // --- API keys (session-authenticated management).
  HttpApiEndpoint.post("apiKeyCreate", "/api-keys", {
    payload: S.ApiKeyCreatePayload,
    success: S.ApiKeyCreatedView,
    error: [S.NotFoundError, S.UnauthorizedError, S.BadRequestError, S.InternalError],
  }),
  HttpApiEndpoint.get("apiKeyList", "/api-keys", {
    success: S.ApiKeyListView,
    error: [S.NotFoundError, S.UnauthorizedError, S.InternalError],
  }),
  HttpApiEndpoint.patch("apiKeyUpdate", "/api-keys/:keyId", {
    params: { keyId: Schema.String },
    payload: S.ApiKeyUpdatePayload,
    success: S.ApiKeyView,
    error: [S.NotFoundError, S.UnauthorizedError, S.BadRequestError, S.InternalError],
  }),
  HttpApiEndpoint.delete("apiKeyDelete", "/api-keys/:keyId", {
    params: { keyId: Schema.String },
    success: HttpApiSchema.NoContent,
    error: [S.NotFoundError, S.UnauthorizedError, S.BadRequestError, S.InternalError],
  }),
  // --- Enterprise SSO (OIDC relying party). 404 when the module is absent.
  // Register is admin-gated (403 for non-admins).
  HttpApiEndpoint.post("ssoRegister", "/sso/register", {
    payload: S.SSORegisterPayload,
    success: S.SSOProviderView,
    error: [
      S.NotFoundError,
      S.UnauthorizedError,
      S.ForbiddenError,
      S.BadRequestError,
      S.InternalError,
    ],
  }),
  // Returns the IdP authorization URL; unknown domain/provider -> 400.
  HttpApiEndpoint.post("signInSSO", "/sign-in/sso", {
    payload: S.SSOSignInPayload,
    success: S.SSOURLView,
    error: [S.NotFoundError, S.BadRequestError, S.InternalError],
  }),
  // Completes the OIDC callback and issues a session (cookie).
  HttpApiEndpoint.post("ssoCallback", "/sso/callback", {
    payload: S.SSOCallbackPayload,
    success: S.AuthSuccess,
    error: [
      S.NotFoundError,
      S.BadRequestError,
      S.ForbiddenError,
      S.InternalError,
      S.TooManyRequestsError,
    ],
  }),
  // SAML assertion consumer service: the form POST the IdP makes on the user's
  // behalf. Same session-issuing tail as `ssoCallback`.
  HttpApiEndpoint.post("samlAcs", "/sso/saml/acs/:providerId", {
    params: { providerId: Schema.String },
    payload: S.SAMLACSPayload,
    success: S.AuthSuccess,
    error: [
      S.NotFoundError,
      S.BadRequestError,
      S.ForbiddenError,
      S.InternalError,
      S.TooManyRequestsError,
    ],
  }),
  // This SP's `EntityDescriptor` for a SAML connection, as XML.
  HttpApiEndpoint.get("samlMetadata", "/sso/saml/metadata/:providerId", {
    params: { providerId: Schema.String },
    success: S.SAMLMetadataView,
    error: [S.NotFoundError, S.BadRequestError, S.InternalError],
  }),
  // --- Google One Tap: generate a server-side nonce for the One Tap prompt.
  // --- 404 when unconfigured.
  HttpApiEndpoint.get("getGoogleOneTapNonce", "/sign-in/google-one-tap/nonce", {
    success: S.GoogleOneTapNonceView,
    error: [S.NotFoundError, S.InternalError],
  }),
  // --- Google One Tap: verify the credential (a Google-signed id_token) and
  // --- sign in by verified email. 404 when unconfigured.
  HttpApiEndpoint.post("signInGoogleOneTap", "/sign-in/google-one-tap", {
    payload: S.GoogleOneTapPayload,
    success: S.AuthSuccess,
    error: [
      S.NotFoundError,
      S.UnauthorizedError,
      S.ForbiddenError,
      S.BadRequestError,
      S.InternalError,
      S.TooManyRequestsError,
    ],
  }),
  // --- JWT: issue a token for the session (`/token`) and serve the JWKS.
  HttpApiEndpoint.get("jwtToken", "/token", {
    success: S.JWTTokenView,
    error: [S.NotFoundError, S.UnauthorizedError, S.InternalError],
  }),
  HttpApiEndpoint.get("jwtJwks", "/jwks", {
    success: S.JwksView,
    error: [S.NotFoundError, S.InternalError],
  }),
  // --- OIDC provider (this server as an OpenID Connect IdP). 404 when the
  // --- module is absent. Client management is admin-gated.
  HttpApiEndpoint.post("oidcRegisterClient", "/oauth2/register", {
    payload: S.OidcRegisterClientPayload,
    success: S.OidcClientCreatedView,
    error: [
      S.NotFoundError,
      S.UnauthorizedError,
      S.ForbiddenError,
      S.BadRequestError,
      S.InternalError,
    ],
  }),
  HttpApiEndpoint.get("oidcListClients", "/oauth2/clients", {
    success: S.OidcClientListView,
    error: [S.NotFoundError, S.UnauthorizedError, S.ForbiddenError, S.InternalError],
  }),
  HttpApiEndpoint.patch("oidcUpdateClient", "/oauth2/clients/:clientId", {
    params: { clientId: Schema.String },
    payload: S.OidcClientUpdatePayload,
    success: S.OidcClientView,
    error: [
      S.NotFoundError,
      S.UnauthorizedError,
      S.ForbiddenError,
      S.BadRequestError,
      S.InternalError,
    ],
  }),
  HttpApiEndpoint.delete("oidcDeleteClient", "/oauth2/clients/:clientId", {
    params: { clientId: Schema.String },
    success: HttpApiSchema.NoContent,
    error: [
      S.NotFoundError,
      S.UnauthorizedError,
      S.ForbiddenError,
      S.BadRequestError,
      S.InternalError,
    ],
  }),
  // Authorization endpoint: answers 302 (to the client's redirect_uri, the
  // login page, or the consent page). Declared NoContent — handlers return
  // raw redirect responses.
  HttpApiEndpoint.get("oidcAuthorize", "/oauth2/authorize", {
    query: {
      response_type: Schema.optional(Schema.String),
      client_id: Schema.optional(Schema.String),
      redirect_uri: Schema.optional(Schema.String),
      scope: Schema.optional(Schema.String),
      state: Schema.optional(Schema.String),
      code_challenge: Schema.optional(Schema.String),
      code_challenge_method: Schema.optional(Schema.String),
      nonce: Schema.optional(Schema.String),
      prompt: Schema.optional(Schema.String),
    },
    success: HttpApiSchema.NoContent,
    error: [S.NotFoundError, S.BadRequestError, S.InternalError],
  }),
  // Consent decision (session-authenticated; posted by the consent page).
  HttpApiEndpoint.post("oidcConsent", "/oauth2/consent", {
    payload: S.OidcConsentPayload,
    success: S.OidcRedirectView,
    error: [S.NotFoundError, S.UnauthorizedError, S.BadRequestError, S.InternalError],
  }),
  // Token endpoint: authorization_code + refresh_token grants. Accepts JSON
  // or form encoding; errors carry the RFC 6749 error code as the message.
  HttpApiEndpoint.post("oidcToken", "/oauth2/token", {
    payload: [S.OidcTokenPayload, S.OidcTokenPayload.pipe(HttpApiSchema.asFormUrlEncoded())],
    success: S.OidcTokenView,
    error: [S.NotFoundError, S.UnauthorizedError, S.BadRequestError, S.InternalError],
  }),
  // UserInfo endpoint: bearer access token -> standard claims.
  HttpApiEndpoint.get("oidcUserInfo", "/oauth2/userinfo", {
    success: S.ClaimsView,
    error: [S.NotFoundError, S.UnauthorizedError, S.InternalError],
  }),
  // --- RFC 7591 dynamic client registration. 404 unless the provider is
  // --- configured with `dynamicRegistration`. Open to anonymous callers
  // --- (optionally gated by an initial access token), so it is rate limited
  // --- and errors use the RFC's `{ error, error_description }` body.
  HttpApiEndpoint.post("oidcDynamicRegister", "/register", {
    payload: S.OidcRegistrationPayload,
    success: S.OidcRegistrationView.pipe(HttpApiSchema.status(201)),
    error: [
      S.OAuthBadRequestError,
      S.NotFoundError,
      S.UnauthorizedError,
      S.ForbiddenError,
      S.TooManyRequestsError,
      S.InternalError,
    ],
  }),
  // --- RFC 7592 registration management, guarded by the registration access
  // --- token issued at registration (`Authorization: Bearer`).
  HttpApiEndpoint.get("oidcReadRegistration", "/register/:clientId", {
    params: { clientId: Schema.String },
    success: S.OidcRegistrationView,
    error: [
      S.OAuthBadRequestError,
      S.NotFoundError,
      S.UnauthorizedError,
      S.ForbiddenError,
      S.InternalError,
    ],
  }),
  HttpApiEndpoint.put("oidcUpdateRegistration", "/register/:clientId", {
    params: { clientId: Schema.String },
    payload: S.OidcRegistrationPayload,
    success: S.OidcRegistrationView,
    error: [
      S.OAuthBadRequestError,
      S.NotFoundError,
      S.UnauthorizedError,
      S.ForbiddenError,
      S.InternalError,
    ],
  }),
  HttpApiEndpoint.delete("oidcDeleteRegistration", "/register/:clientId", {
    params: { clientId: Schema.String },
    success: HttpApiSchema.NoContent,
    error: [
      S.OAuthBadRequestError,
      S.NotFoundError,
      S.UnauthorizedError,
      S.ForbiddenError,
      S.InternalError,
    ],
  }),
  // OIDC discovery + JWKS (shared with the JWT module's signing keys).
  HttpApiEndpoint.get("oidcDiscovery", "/.well-known/openid-configuration", {
    success: S.ClaimsView,
    error: [S.NotFoundError, S.InternalError],
  }),
  // RFC 8414 authorization server metadata — the document MCP clients fetch.
  HttpApiEndpoint.get(
    "oauthAuthorizationServerMetadata",
    "/.well-known/oauth-authorization-server",
    {
      success: S.ClaimsView,
      error: [S.NotFoundError, S.InternalError],
    },
  ),
  HttpApiEndpoint.get("oidcJwks", "/.well-known/jwks.json", {
    success: S.JwksView,
    error: [S.NotFoundError, S.InternalError],
  }),
);

/**
 * SCIM 2.0 provisioning (RFC 7644), mounted under `/scim/v2`.
 *
 * A group of its own rather than more endpoints on `authGroup`, because SCIM
 * is a different protocol with a different audience: every route here is
 * authenticated by an organization's bearer provisioning token instead of a
 * session cookie, speaks `application/scim+json`, and reports failures in
 * SCIM's own error shape. Keeping it separate means none of that leaks into
 * the session API — and an app that never provisions simply gets `404`s.
 *
 * Resource names are capitalized (`/Users`, `/Groups`) because SCIM says so and
 * IdPs build the paths literally.
 */
export const scimGroup = HttpApiGroup.make("scim")
  .add(
    HttpApiEndpoint.post("scimCreateUser", "/Users", {
      payload: S.SCIMUserPayload.pipe(S.asSCIMJson),
      success: S.SCIMUserView.pipe(HttpApiSchema.status(201), S.asSCIMJson),
      error: S.SCIMErrors,
    }),
  )
  .add(
    HttpApiEndpoint.get("scimListUsers", "/Users", {
      query: {
        filter: Schema.optional(Schema.String),
        startIndex: Schema.optional(Schema.String),
        count: Schema.optional(Schema.String),
      },
      success: S.SCIMUserListView.pipe(S.asSCIMJson),
      error: S.SCIMErrors,
    }),
  )
  .add(
    HttpApiEndpoint.get("scimGetUser", "/Users/:id", {
      params: { id: Schema.String },
      success: S.SCIMUserView.pipe(S.asSCIMJson),
      error: S.SCIMErrors,
    }),
  )
  .add(
    HttpApiEndpoint.put("scimReplaceUser", "/Users/:id", {
      params: { id: Schema.String },
      payload: S.SCIMUserPayload.pipe(S.asSCIMJson),
      success: S.SCIMUserView.pipe(S.asSCIMJson),
      error: S.SCIMErrors,
    }),
  )
  .add(
    HttpApiEndpoint.patch("scimPatchUser", "/Users/:id", {
      params: { id: Schema.String },
      payload: S.SCIMPatchPayload.pipe(S.asSCIMJson),
      success: S.SCIMUserView.pipe(S.asSCIMJson),
      error: S.SCIMErrors,
    }),
  )
  // A soft disable, not a hard delete — see `SCIMService.deactivateUser`.
  .add(
    HttpApiEndpoint.delete("scimDeleteUser", "/Users/:id", {
      params: { id: Schema.String },
      success: HttpApiSchema.NoContent,
      error: S.SCIMErrors,
    }),
  )
  .add(
    HttpApiEndpoint.post("scimCreateGroup", "/Groups", {
      payload: S.SCIMGroupPayload.pipe(S.asSCIMJson),
      success: S.SCIMGroupView.pipe(HttpApiSchema.status(201), S.asSCIMJson),
      error: S.SCIMErrors,
    }),
  )
  .add(
    HttpApiEndpoint.get("scimListGroups", "/Groups", {
      query: {
        filter: Schema.optional(Schema.String),
        startIndex: Schema.optional(Schema.String),
        count: Schema.optional(Schema.String),
      },
      success: S.SCIMGroupListView.pipe(S.asSCIMJson),
      error: S.SCIMErrors,
    }),
  )
  .add(
    HttpApiEndpoint.get("scimGetGroup", "/Groups/:id", {
      params: { id: Schema.String },
      success: S.SCIMGroupView.pipe(S.asSCIMJson),
      error: S.SCIMErrors,
    }),
  )
  .add(
    HttpApiEndpoint.put("scimReplaceGroup", "/Groups/:id", {
      params: { id: Schema.String },
      payload: S.SCIMGroupPayload.pipe(S.asSCIMJson),
      success: S.SCIMGroupView.pipe(S.asSCIMJson),
      error: S.SCIMErrors,
    }),
  )
  .add(
    HttpApiEndpoint.patch("scimPatchGroup", "/Groups/:id", {
      params: { id: Schema.String },
      payload: S.SCIMPatchPayload.pipe(S.asSCIMJson),
      success: S.SCIMGroupView.pipe(S.asSCIMJson),
      error: S.SCIMErrors,
    }),
  )
  .add(
    HttpApiEndpoint.delete("scimDeleteGroup", "/Groups/:id", {
      params: { id: Schema.String },
      success: HttpApiSchema.NoContent,
      error: S.SCIMErrors,
    }),
  )
  // Discovery (RFC 7644 §4). An IdP reads these before it provisions anything
  // to learn which optional features to use; they are unauthenticated because
  // they describe the server, not any tenant's data.
  .add(
    HttpApiEndpoint.get("scimServiceProviderConfig", "/ServiceProviderConfig", {
      success: S.SCIMDocumentView.pipe(S.asSCIMJson),
      error: S.SCIMErrors,
    }),
  )
  .add(
    HttpApiEndpoint.get("scimResourceTypes", "/ResourceTypes", {
      success: S.SCIMDocumentView.pipe(S.asSCIMJson),
      error: S.SCIMErrors,
    }),
  )
  .add(
    HttpApiEndpoint.get("scimSchemas", "/Schemas", {
      success: S.SCIMDocumentView.pipe(S.asSCIMJson),
      error: S.SCIMErrors,
    }),
  )
  .prefix("/scim/v2");

/** The complete auth API, annotated with OpenAPI document metadata. */
export const AuthApi = HttpApi.make("AuthApi")
  .add(authGroup)
  .add(scimGroup)
  .annotateMerge(
    OpenApi.annotations({
      title: "effect-auth",
      version: "1.0.0",
      description:
        "HTTP protocol for effect-auth: email/password, sessions, email verification and " +
        "password reset, magic link, email OTP, multi-factor authentication, and SCIM 2.0 " +
        "provisioning.",
    }),
  );

/**
 * Derive the OpenAPI 3.1 document for the auth API from the {@link AuthApi}
 * contract. The document describes every endpoint path together with its
 * request/response and error schemas (each carrying its HTTP status code).
 *
 * Served at `GET {prefix}/openapi.json` when `HTTPServer.make` is created
 * with `{ docs: true }`, and consumable by any OpenAPI tooling.
 */
export const getOpenApiSpec = (): OpenApi.OpenAPISpec => OpenApi.fromApi(AuthApi);
