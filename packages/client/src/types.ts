/**
 * Wire types for the effect-auth HTTP protocol, re-exported type-only so
 * browser clients can share the contract's shapes without importing any
 * server code (these erase entirely at compile time).
 *
 * @module types
 */
import type * as Auth from "effect-auth";

export type UserView = Auth.Http.UserView;
export type SessionView = Auth.Http.SessionView;
export type SessionWithUserView = Auth.Http.SessionWithUserView;
export type AuthSuccess = Auth.Http.AuthSuccess;
export type SecondFactorChallengeView = Auth.Http.SecondFactorChallengeView;
export type StatusResponse = Auth.Http.StatusResponse;
export type SignUpPayload = Auth.Http.SignUpPayload;
export type SignInPayload = Auth.Http.SignInPayload;
export type ChangePasswordPayload = Auth.Http.ChangePasswordPayload;
export type UpdateUserPayload = Auth.Http.UpdateUserPayload;
export type EmailOtpPurpose = Auth.Http.EmailOtpPurpose;
export type TwoFactorEnableView = Auth.Http.TwoFactorEnableView;
export type BackupCodesView = Auth.Http.BackupCodesView;
export type ChangeEmailRequestPayload = Auth.Http.ChangeEmailRequestPayload;
export type ChangeEmailConfirmPayload = Auth.Http.ChangeEmailConfirmPayload;
export type DeleteUserConfirmPayload = Auth.Http.DeleteUserConfirmPayload;
export type UsernameSignInPayload = Auth.Http.UsernameSignInPayload;
export type JwtTokenView = Auth.Http.JwtTokenView;
export type MultiSessionListView = Auth.Http.MultiSessionListView;
export type MultiSessionActionPayload = Auth.Http.MultiSessionActionPayload;
