/**
 * OAuth 2.0 and OpenID Connect types for effect-auth
 *
 * Provides type definitions for OAuth2 flows, provider configurations,
 * and related data structures.
 */

import * as Effect from "effect/Effect"
import type { AuthError, OAuthProviderError } from "./errors.js"

/**
 * OAuth2 provider configuration
 */
export interface OAuthProviderConfig {
  readonly clientId: string
  readonly clientSecret: string
  readonly redirectUri: string
  readonly authorizationEndpoint: string
  readonly tokenEndpoint: string
  readonly userInfoEndpoint?: string
  readonly scopes: readonly string[]
}

/**
 * OAuth2 state for CSRF protection
 */
export interface OAuthState {
  readonly state: string
  readonly provider: string
  readonly codeVerifier?: string // For PKCE
  readonly returnTo?: string
  readonly createdAt: number
  readonly expiresAt: number
}

/**
 * OAuth account linking to user
 */
export interface OAuthAccount {
  readonly id: string
  readonly userId: string
  readonly provider: string
  readonly providerId: string
  readonly email?: string
  readonly name?: string
  readonly picture?: string
  readonly accessToken: string
  readonly refreshToken?: string
  readonly expiresAt?: number
  readonly createdAt: number
  readonly updatedAt: number
}

/**
 * OAuth2 token response
 */
export interface OAuthTokenResponse {
  readonly access_token: string
  readonly token_type: string
  readonly expires_in?: number
  readonly refresh_token?: string
  readonly scope?: string
  readonly id_token?: string // For OIDC
}

/**
 * User info from OAuth provider
 */
export interface OAuthUserInfo {
  readonly id: string
  readonly email?: string
  readonly email_verified?: boolean
  readonly name?: string
  readonly picture?: string
  readonly given_name?: string
  readonly family_name?: string
  readonly locale?: string
  readonly [key: string]: unknown
}

/**
 * Authorization URL generation result
 */
export interface AuthorizationUrlResult {
  readonly url: string
  readonly state: string
  readonly codeVerifier?: string
}

/**
 * OAuth callback result
 */
export interface OAuthCallbackResult {
  readonly account: OAuthAccount
  readonly isNewUser: boolean
  readonly user?: {
    readonly id: string
    readonly email?: string
    readonly name?: string
  }
}

/**
 * Storage interface for OAuth state (temporary, Redis/memory)
 */
export interface OAuthStateStore {
  readonly create: (
    state: OAuthState
  ) => Effect.Effect<OAuthState, AuthError>
  readonly get: (
    state: string
  ) => Effect.Effect<OAuthState, AuthError>
  readonly delete: (state: string) => Effect.Effect<void, AuthError>
}

/**
 * Storage interface for OAuth accounts (persistent, database)
 */
export interface OAuthAccountStore {
  readonly create: (
    account: OAuthAccount
  ) => Effect.Effect<OAuthAccount, AuthError>
  readonly get: (
    provider: string,
    providerId: string
  ) => Effect.Effect<OAuthAccount | null, AuthError>
  readonly getByUserId: (
    userId: string
  ) => Effect.Effect<readonly OAuthAccount[], AuthError>
  readonly update: (
    account: OAuthAccount
  ) => Effect.Effect<OAuthAccount, AuthError>
  readonly linkToUser: (
    userId: string,
    account: OAuthAccount
  ) => Effect.Effect<void, AuthError>
  readonly unlinkFromUser: (
    userId: string,
    provider: string
  ) => Effect.Effect<void, AuthError>
  readonly delete: (
    provider: string,
    providerId: string
  ) => Effect.Effect<void, AuthError>
}

/**
 * OAuth provider interface
 */
export interface OAuthProvider {
  readonly name: string
  readonly config: OAuthProviderConfig
  readonly generateAuthorizationUrl: (
    scopes?: readonly string[]
  ) => Effect.Effect<
    AuthorizationUrlResult,
    OAuthProviderError | AuthError,
    OAuthStateStore
  >
  readonly exchangeCode: (
    code: string,
    codeVerifier?: string
  ) => Effect.Effect<OAuthTokenResponse, OAuthProviderError>
  readonly getUserInfo: (
    accessToken: string
  ) => Effect.Effect<OAuthUserInfo, OAuthProviderError>
}
