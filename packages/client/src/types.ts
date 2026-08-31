/**
 * Wire types for the effect-auth HTTP protocol, re-exported type-only so
 * browser clients can share the contract's shapes without importing any
 * server code (these erase entirely at compile time).
 *
 * @module types
 */
import type * as Auth from "@thomasfosterau/effect-auth";

// --- Core: users, sessions, identifiers ---------------------------------------

export type UserView = Auth.HTTP.UserView;
export type SessionView = Auth.HTTP.SessionView;
export type SessionWithUserView = Auth.HTTP.SessionWithUserView;
export type IdentifierView = Auth.HTTP.IdentifierView;
export type IdentifierListView = Auth.HTTP.IdentifierListView;
export type AuthSuccess = Auth.HTTP.AuthSuccess;
export type SecondFactorChallengeView = Auth.HTTP.SecondFactorChallengeView;
export type StatusResponse = Auth.HTTP.StatusResponse;
export type SignUpPayload = Auth.HTTP.SignUpPayload;
export type SignInPayload = Auth.HTTP.SignInPayload;
export type ChangePasswordPayload = Auth.HTTP.ChangePasswordPayload;
export type UpdateUserPayload = Auth.HTTP.UpdateUserPayload;

// --- Account management -------------------------------------------------------

export type ChangeEmailRequestPayload = Auth.HTTP.ChangeEmailRequestPayload;
export type ChangeEmailConfirmPayload = Auth.HTTP.ChangeEmailConfirmPayload;
export type DeleteUserConfirmPayload = Auth.HTTP.DeleteUserConfirmPayload;

// --- Alternative sign-in surfaces ---------------------------------------------

export type UsernameSignInPayload = Auth.HTTP.UsernameSignInPayload;
export type EmailOTPPurpose = Auth.HTTP.EmailOTPPurpose;
export type EmailOTPSendPayload = Auth.HTTP.EmailOTPSendPayload;
export type EmailOTPSignInPayload = Auth.HTTP.EmailOTPSignInPayload;
export type PhoneOTPPurpose = Auth.HTTP.PhoneOTPPurpose;
export type PhoneOTPSendPayload = Auth.HTTP.PhoneOTPSendPayload;
export type PhoneOTPSignInPayload = Auth.HTTP.PhoneOTPSignInPayload;
export type MagicLinkSendPayload = Auth.HTTP.MagicLinkSendPayload;
export type MagicLinkVerifyPayload = Auth.HTTP.MagicLinkVerifyPayload;
export type GoogleOneTapNonceView = Auth.HTTP.GoogleOneTapNonceView;
export type GoogleOneTapPayload = Auth.HTTP.GoogleOneTapPayload;

// --- Multi-session & device authorization -------------------------------------

export type MultiSessionListView = Auth.HTTP.MultiSessionListView;
export type MultiSessionActionPayload = Auth.HTTP.MultiSessionActionPayload;
export type DeviceCodePayload = Auth.HTTP.DeviceCodePayload;
export type DeviceCodeView = Auth.HTTP.DeviceCodeView;
export type DeviceTokenPayload = Auth.HTTP.DeviceTokenPayload;
export type DeviceUserCodePayload = Auth.HTTP.DeviceUserCodePayload;

// --- Multi-factor -------------------------------------------------------------

export type MultiFactorEnableView = Auth.HTTP.MultiFactorEnableView;
export type MultiFactorPasswordPayload = Auth.HTTP.MultiFactorPasswordPayload;
export type MultiFactorConfirmPayload = Auth.HTTP.MultiFactorConfirmPayload;
export type MultiFactorVerifyPayload = Auth.HTTP.MultiFactorVerifyPayload;
export type BackupCodesView = Auth.HTTP.BackupCodesView;

// --- Organization: orgs, members, invitations, teams, roles -------------------

export type OrganizationView = Auth.HTTP.OrganizationView;
export type OrganizationListView = Auth.HTTP.OrganizationListView;
export type FullOrganizationView = Auth.HTTP.FullOrganizationView;
export type CreateOrganizationPayload = Auth.HTTP.CreateOrganizationPayload;
export type UpdateOrganizationPayload = Auth.HTTP.UpdateOrganizationPayload;
export type SetActiveOrganizationPayload = Auth.HTTP.SetActiveOrganizationPayload;
export type MemberView = Auth.HTTP.MemberView;
export type AddMemberPayload = Auth.HTTP.AddMemberPayload;
export type UpdateMemberRolePayload = Auth.HTTP.UpdateMemberRolePayload;
export type InvitationView = Auth.HTTP.InvitationView;
export type InvitationListView = Auth.HTTP.InvitationListView;
export type InviteMemberPayload = Auth.HTTP.InviteMemberPayload;
export type TeamView = Auth.HTTP.TeamView;
export type TeamListView = Auth.HTTP.TeamListView;
export type TeamMemberView = Auth.HTTP.TeamMemberView;
export type TeamMemberListView = Auth.HTTP.TeamMemberListView;
export type CreateTeamPayload = Auth.HTTP.CreateTeamPayload;
export type UpdateTeamPayload = Auth.HTTP.UpdateTeamPayload;
export type AddTeamMemberPayload = Auth.HTTP.AddTeamMemberPayload;
export type OrgRoleView = Auth.HTTP.OrgRoleView;
export type OrgRoleListView = Auth.HTTP.OrgRoleListView;
export type UpsertOrgRolePayload = Auth.HTTP.UpsertOrgRolePayload;

// --- API keys -----------------------------------------------------------------

export type ApiKeyView = Auth.HTTP.ApiKeyView;
export type ApiKeyListView = Auth.HTTP.ApiKeyListView;
export type ApiKeyCreatedView = Auth.HTTP.ApiKeyCreatedView;
export type ApiKeyCreatePayload = Auth.HTTP.ApiKeyCreatePayload;
export type ApiKeyUpdatePayload = Auth.HTTP.ApiKeyUpdatePayload;

// --- JWT ----------------------------------------------------------------------

export type JWTTokenView = Auth.HTTP.JWTTokenView;
export type JwksView = Auth.HTTP.JwksView;

// --- Admin --------------------------------------------------------------------

export type AdminUserListView = Auth.HTTP.AdminUserListView;
export type AdminListUsersPayload = Auth.HTTP.AdminListUsersPayload;
export type AdminSetRolePayload = Auth.HTTP.AdminSetRolePayload;
export type AdminBanUserPayload = Auth.HTTP.AdminBanUserPayload;
export type AdminUserActionPayload = Auth.HTTP.AdminUserActionPayload;

// --- Enterprise SSO -----------------------------------------------------------

export type SSOProviderView = Auth.HTTP.SSOProviderView;
export type SSORegisterPayload = Auth.HTTP.SSORegisterPayload;
export type SSOSignInPayload = Auth.HTTP.SSOSignInPayload;
export type SSOURLView = Auth.HTTP.SSOURLView;
export type SSOCallbackPayload = Auth.HTTP.SSOCallbackPayload;

// --- OIDC provider (client management + consent) ------------------------------

export type OidcClientView = Auth.HTTP.OidcClientView;
export type OidcClientListView = Auth.HTTP.OidcClientListView;
export type OidcClientCreatedView = Auth.HTTP.OidcClientCreatedView;
export type OidcRegisterClientPayload = Auth.HTTP.OidcRegisterClientPayload;
export type OidcClientUpdatePayload = Auth.HTTP.OidcClientUpdatePayload;
export type OidcConsentPayload = Auth.HTTP.OidcConsentPayload;
export type OidcRedirectView = Auth.HTTP.OidcRedirectView;
