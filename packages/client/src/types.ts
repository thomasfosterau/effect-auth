/**
 * Wire types for the effect-auth HTTP protocol, re-exported type-only so
 * browser clients can share the contract's shapes without importing any
 * server code (these erase entirely at compile time).
 *
 * @module types
 */
import type * as Auth from "effect-auth";

export type UserView = Auth.HTTP.UserView;
export type SessionView = Auth.HTTP.SessionView;
export type SessionWithUserView = Auth.HTTP.SessionWithUserView;
export type AuthSuccess = Auth.HTTP.AuthSuccess;
export type SecondFactorChallengeView = Auth.HTTP.SecondFactorChallengeView;
export type StatusResponse = Auth.HTTP.StatusResponse;
export type SignUpPayload = Auth.HTTP.SignUpPayload;
export type SignInPayload = Auth.HTTP.SignInPayload;
export type ChangePasswordPayload = Auth.HTTP.ChangePasswordPayload;
export type UpdateUserPayload = Auth.HTTP.UpdateUserPayload;
export type EmailOTPPurpose = Auth.HTTP.EmailOTPPurpose;
export type TwoFactorEnableView = Auth.HTTP.TwoFactorEnableView;
export type BackupCodesView = Auth.HTTP.BackupCodesView;
export type ChangeEmailRequestPayload = Auth.HTTP.ChangeEmailRequestPayload;
export type ChangeEmailConfirmPayload = Auth.HTTP.ChangeEmailConfirmPayload;
export type DeleteUserConfirmPayload = Auth.HTTP.DeleteUserConfirmPayload;
export type UsernameSignInPayload = Auth.HTTP.UsernameSignInPayload;
export type JWTTokenView = Auth.HTTP.JWTTokenView;
export type MultiSessionListView = Auth.HTTP.MultiSessionListView;
export type MultiSessionActionPayload = Auth.HTTP.MultiSessionActionPayload;
