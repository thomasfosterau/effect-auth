/**
 * OAuth 2.0 and OpenID Connect types for effect-auth
 *
 * Provides type definitions for OAuth2 flows, provider configurations,
 * and related data structures.
 */

import { Context, Effect, Layer } from "effect";
import {
  AuthError,
  OAuthProviderError,
  OAuthStateNotFoundError,
  OAuthStateExpiredError,
} from "./Errors.js";

/**
 * OAuth2 provider configuration
 */
export interface OAuthProviderConfig {
  readonly clientId: string;
  readonly clientSecret: string;
  readonly redirectUri: string;
  readonly authorizationEndpoint: string;
  readonly tokenEndpoint: string;
  readonly userInfoEndpoint?: string;
  readonly scopes: readonly string[];
}

/**
 * OAuth2 state for CSRF protection
 */
export interface OAuthState {
  readonly state: string;
  readonly provider: string;
  readonly codeVerifier?: string; // For PKCE
  readonly returnTo?: string;
  readonly createdAt: number;
  readonly expiresAt: number;
}

/**
 * OAuth account linking to user
 */
export interface OAuthAccount {
  readonly id: string;
  readonly userId: string;
  readonly provider: string;
  readonly providerId: string;
  readonly email?: string;
  readonly name?: string;
  readonly picture?: string;
  readonly accessToken: string;
  readonly refreshToken?: string;
  readonly expiresAt?: number;
  readonly createdAt: number;
  readonly updatedAt: number;
}

/**
 * OAuth2 token response
 */
export interface OAuthTokenResponse {
  readonly access_token: string;
  readonly token_type: string;
  readonly expires_in?: number;
  readonly refresh_token?: string;
  readonly scope?: string;
  readonly id_token?: string; // For OIDC
}

/**
 * User info from OAuth provider
 */
export interface OAuthUserInfo {
  readonly id: string;
  readonly email?: string;
  readonly email_verified?: boolean;
  readonly name?: string;
  readonly picture?: string;
  readonly given_name?: string;
  readonly family_name?: string;
  readonly locale?: string;
  readonly [key: string]: unknown;
}

/**
 * Authorization URL generation result
 */
export interface AuthorizationUrlResult {
  readonly url: string;
  readonly state: string;
  readonly codeVerifier?: string;
}

/**
 * OAuth callback result
 */
export interface OAuthCallbackResult {
  readonly account: OAuthAccount;
  readonly isNewUser: boolean;
  readonly user?: {
    readonly id: string;
    readonly email?: string;
    readonly name?: string;
  };
}

/**
 * Storage interface for OAuth state (temporary, Redis/memory)
 */
export interface OAuthStateStore {
  readonly create: (state: OAuthState) => Effect.Effect<OAuthState, AuthError>;
  readonly get: (state: string) => Effect.Effect<OAuthState, AuthError>;
  readonly delete: (state: string) => Effect.Effect<void, AuthError>;
}

/**
 * Storage interface for OAuth accounts (persistent, database)
 */
export interface OAuthAccountStore {
  readonly create: (account: OAuthAccount) => Effect.Effect<OAuthAccount, AuthError>;
  readonly get: (
    provider: string,
    providerId: string,
  ) => Effect.Effect<OAuthAccount | null, AuthError>;
  readonly getByUserId: (userId: string) => Effect.Effect<readonly OAuthAccount[], AuthError>;
  readonly update: (account: OAuthAccount) => Effect.Effect<OAuthAccount, AuthError>;
  readonly linkToUser: (userId: string, account: OAuthAccount) => Effect.Effect<void, AuthError>;
  readonly unlinkFromUser: (userId: string, provider: string) => Effect.Effect<void, AuthError>;
  readonly delete: (provider: string, providerId: string) => Effect.Effect<void, AuthError>;
}

/**
 * OAuth provider interface
 */
export interface OAuthProvider {
  readonly name: string;
  readonly config: OAuthProviderConfig;
  readonly generateAuthorizationUrl: (
    scopes?: readonly string[],
  ) => Effect.Effect<AuthorizationUrlResult, OAuthProviderError | AuthError, OAuthStateStoreTag>;
  readonly exchangeCode: (
    code: string,
    codeVerifier?: string,
  ) => Effect.Effect<OAuthTokenResponse, OAuthProviderError>;
  readonly getUserInfo: (accessToken: string) => Effect.Effect<OAuthUserInfo, OAuthProviderError>;
}

/**
 * OAuth 2.0 and OpenID Connect implementation for effect-auth
 *
 * Provides a generic OAuth2 client with authorization code flow,
 * PKCE support, and pre-built provider configurations.
 *
 * @module oauth
 */
import * as crypto from "node:crypto";

/**
 * OAuth state store context tag
 */
export class OAuthStateStoreTag extends Context.Service<OAuthStateStoreTag, OAuthStateStore>()(
  "@effect-auth/OAuthStateStore",
) {}

// Public ergonomic alias
export const OAuthStateStore = OAuthStateStoreTag;

/**
 * OAuth account store context tag
 */
export class OAuthAccountStoreTag extends Context.Service<
  OAuthAccountStoreTag,
  OAuthAccountStore
>()("@effect-auth/OAuthAccountStore") {}

// Public ergonomic alias
export const OAuthAccountStore = OAuthAccountStoreTag;

/**
 * Generate a cryptographically secure random state parameter
 */
export const generateState = (): Effect.Effect<string, never> =>
  Effect.sync(() => crypto.randomBytes(32).toString("base64url"));

/**
 * Generate PKCE code verifier and challenge
 */
export const generatePKCE = (): Effect.Effect<
  { codeVerifier: string; codeChallenge: string },
  never
> =>
  Effect.sync(() => {
    const codeVerifier = crypto.randomBytes(32).toString("base64url");
    const codeChallenge = crypto.createHash("sha256").update(codeVerifier).digest("base64url");
    return { codeVerifier, codeChallenge };
  });

/**
 * Create an OAuth provider
 */
export const makeOAuthProvider = (
  name: string,
  config: OAuthProviderConfig,
  usePKCE = true,
): OAuthProvider => ({
  name,
  config,

  generateAuthorizationUrl: (customScopes?: readonly string[]) =>
    Effect.gen(function* () {
      const stateStore = yield* OAuthStateStoreTag;
      const state = yield* generateState();

      // Generate PKCE if enabled
      const pkce = usePKCE ? yield* generatePKCE() : undefined;

      // Create state entry
      const stateEntry: OAuthState = {
        state,
        provider: name,
        ...(pkce?.codeVerifier && { codeVerifier: pkce.codeVerifier }),
        createdAt: Date.now(),
        expiresAt: Date.now() + 10 * 60 * 1000, // 10 minutes
      };

      yield* stateStore.create(stateEntry);

      // Build authorization URL
      const scopes = customScopes ?? config.scopes;
      const params = new URLSearchParams({
        client_id: config.clientId,
        redirect_uri: config.redirectUri,
        response_type: "code",
        scope: scopes.join(" "),
        state,
      });

      if (pkce) {
        params.set("code_challenge", pkce.codeChallenge);
        params.set("code_challenge_method", "S256");
      }

      const url = `${config.authorizationEndpoint}?${params.toString()}`;

      return {
        url,
        state,
        ...(pkce?.codeVerifier && { codeVerifier: pkce.codeVerifier }),
      } satisfies AuthorizationUrlResult;
    }),

  exchangeCode: (code: string, codeVerifier?: string) =>
    Effect.gen(function* () {
      const params = new URLSearchParams({
        client_id: config.clientId,
        client_secret: config.clientSecret,
        code,
        grant_type: "authorization_code",
        redirect_uri: config.redirectUri,
      });

      if (codeVerifier) {
        params.set("code_verifier", codeVerifier);
      }

      const response = yield* Effect.tryPromise({
        try: () =>
          fetch(config.tokenEndpoint, {
            method: "POST",
            headers: {
              "Content-Type": "application/x-www-form-urlencoded",
              Accept: "application/json",
            },
            body: params.toString(),
          }),
        catch: (cause) =>
          new OAuthProviderError({
            message: `Failed to exchange code with ${name}`,
            provider: name,
            cause,
          }),
      });

      if (!response.ok) {
        const errorText = yield* Effect.promise(() => response.text());
        return yield* Effect.fail(
          new OAuthProviderError({
            message: `Token exchange failed: ${errorText}`,
            provider: name,
          }),
        );
      }

      const data = (yield* Effect.promise(() => response.json())) as OAuthTokenResponse;

      return data;
    }),

  getUserInfo: (accessToken: string) =>
    Effect.gen(function* () {
      if (!config.userInfoEndpoint) {
        return yield* Effect.fail(
          new OAuthProviderError({
            message: `Provider ${name} does not have a user info endpoint`,
            provider: name,
          }),
        );
      }

      const response = yield* Effect.tryPromise({
        try: () =>
          fetch(config.userInfoEndpoint!, {
            headers: {
              Authorization: `Bearer ${accessToken}`,
              Accept: "application/json",
            },
          }),
        catch: (cause) =>
          new OAuthProviderError({
            message: `Failed to get user info from ${name}`,
            provider: name,
            cause,
          }),
      });

      if (!response.ok) {
        const errorText = yield* Effect.promise(() => response.text());
        return yield* Effect.fail(
          new OAuthProviderError({
            message: `User info request failed: ${errorText}`,
            provider: name,
          }),
        );
      }

      const data = (yield* Effect.promise(() => response.json())) as OAuthUserInfo;

      return data;
    }),
});

/**
 * OAuth service for managing OAuth flows
 */
export interface OAuthService {
  readonly generateAuthorizationUrl: (
    provider: string,
    options?: { scopes?: readonly string[]; returnTo?: string },
  ) => Effect.Effect<AuthorizationUrlResult, AuthError | OAuthProviderError, OAuthStateStoreTag>;

  readonly handleCallback: (
    state: string,
    code: string,
    options?: { linkToUserId?: string },
  ) => Effect.Effect<
    OAuthCallbackResult,
    AuthError | OAuthProviderError | OAuthStateNotFoundError | OAuthStateExpiredError,
    OAuthStateStoreTag | OAuthAccountStoreTag
  >;

  readonly linkAccount: (
    userId: string,
    provider: string,
    code: string,
    state: string,
  ) => Effect.Effect<
    OAuthAccount,
    AuthError | OAuthProviderError | OAuthStateNotFoundError | OAuthStateExpiredError,
    OAuthStateStoreTag | OAuthAccountStoreTag
  >;

  readonly unlinkAccount: (
    userId: string,
    provider: string,
  ) => Effect.Effect<void, AuthError, OAuthAccountStoreTag>;

  readonly refreshAccessToken: (
    userId: string,
    provider: string,
  ) => Effect.Effect<string, AuthError | OAuthProviderError, OAuthAccountStoreTag>;
}

export class OAuthServiceTag extends Context.Service<OAuthServiceTag, OAuthService>()(
  "@effect-auth/OAuthService",
) {}

// Public ergonomic alias
export const OAuthService = OAuthServiceTag;

/**
 * Create an OAuth service with configured providers
 */
export const makeOAuthService = (
  providers: Record<string, OAuthProvider>,
): Effect.Effect<OAuthService, never> =>
  Effect.sync(
    (): OAuthService => ({
      generateAuthorizationUrl: (provider, options) =>
        Effect.gen(function* () {
          const providerInstance = providers[provider];
          if (!providerInstance) {
            return yield* Effect.fail(
              new OAuthProviderError({
                message: `Provider ${provider} not found`,
                provider,
              }),
            );
          }

          const result = yield* providerInstance.generateAuthorizationUrl(options?.scopes);

          // Update state with returnTo if provided
          if (options?.returnTo) {
            const stateStore = yield* OAuthStateStoreTag;
            const stateEntry = yield* stateStore.get(result.state);
            // Delete old state and create new one with returnTo
            yield* stateStore.delete(result.state);
            yield* stateStore.create({
              ...stateEntry,
              returnTo: options.returnTo,
            });
          }

          return result;
        }),

      handleCallback: (state, code, options) =>
        Effect.gen(function* () {
          const stateStore = yield* OAuthStateStoreTag;
          const accountStore = yield* OAuthAccountStoreTag;

          // Verify state
          const stateEntry = yield* Effect.catchTag(stateStore.get(state), "AuthError", () =>
            Effect.fail(
              new OAuthStateNotFoundError({
                message: "OAuth state not found or expired",
                state,
              }),
            ),
          );

          // Check expiration
          if (Date.now() > stateEntry.expiresAt) {
            yield* stateStore.delete(state);
            return yield* Effect.fail(
              new OAuthStateExpiredError({
                message: "OAuth state expired",
                state,
              }),
            );
          }

          const providerInstance = providers[stateEntry.provider];
          if (!providerInstance) {
            return yield* Effect.fail(
              new OAuthProviderError({
                message: `Provider ${stateEntry.provider} not found`,
                provider: stateEntry.provider,
              }),
            );
          }

          // Exchange code for tokens
          const tokens = yield* providerInstance.exchangeCode(code, stateEntry.codeVerifier);

          // Get user info
          const userInfo = yield* providerInstance.getUserInfo(tokens.access_token);

          // Clean up state
          yield* stateStore.delete(state);

          // Check if account exists
          const existingAccount = yield* accountStore.get(stateEntry.provider, userInfo.id);

          if (existingAccount) {
            // Update existing account
            const updatedAccount: OAuthAccount = {
              ...existingAccount,
              accessToken: tokens.access_token,
              ...(tokens.refresh_token && {
                refreshToken: tokens.refresh_token,
              }),
              ...(tokens.expires_in && {
                expiresAt: Date.now() + tokens.expires_in * 1000,
              }),
              updatedAt: Date.now(),
            };
            yield* accountStore.update(updatedAccount);

            return {
              account: updatedAccount,
              isNewUser: false,
            } satisfies OAuthCallbackResult;
          }

          // Create new account
          // Note: For new accounts without linkToUserId, we create an unlinked account
          // with empty userId. The caller should link it to a user after creating
          // the user record in their database.
          const newAccount: OAuthAccount = {
            id: crypto.randomBytes(16).toString("hex"),
            userId: options?.linkToUserId ?? "",
            provider: stateEntry.provider,
            providerId: userInfo.id,
            ...(userInfo.email && { email: userInfo.email }),
            ...(userInfo.name && { name: userInfo.name }),
            ...(userInfo.picture && { picture: userInfo.picture }),
            accessToken: tokens.access_token,
            ...(tokens.refresh_token && { refreshToken: tokens.refresh_token }),
            ...(tokens.expires_in && {
              expiresAt: Date.now() + tokens.expires_in * 1000,
            }),
            createdAt: Date.now(),
            updatedAt: Date.now(),
          };

          yield* accountStore.create(newAccount);

          return {
            account: newAccount,
            isNewUser: true,
            ...(options?.linkToUserId
              ? {
                  user: {
                    id: newAccount.userId,
                    ...(userInfo.email && { email: userInfo.email }),
                    ...(userInfo.name && { name: userInfo.name }),
                  },
                }
              : {}),
          } satisfies OAuthCallbackResult;
        }),

      linkAccount: (userId, provider, code, state) =>
        Effect.gen(function* () {
          // Properly implement OAuth flow for account linking
          // This follows the same flow as handleCallback but links to existing user
          const stateStore = yield* OAuthStateStoreTag;
          const accountStore = yield* OAuthAccountStoreTag;

          // Verify state
          const stateEntry = yield* Effect.catchTag(stateStore.get(state), "AuthError", () =>
            Effect.fail(
              new OAuthStateNotFoundError({
                message: "OAuth state not found or expired",
                state,
              }),
            ),
          );

          if (stateEntry.provider !== provider) {
            return yield* Effect.fail(
              new OAuthProviderError({
                message: `State provider mismatch: expected ${provider}, got ${stateEntry.provider}`,
                provider,
              }),
            );
          }

          // Check expiration
          if (Date.now() > stateEntry.expiresAt) {
            yield* stateStore.delete(state);
            return yield* Effect.fail(
              new OAuthStateExpiredError({
                message: "OAuth state expired",
                state,
              }),
            );
          }

          const providerInstance = providers[provider];
          if (!providerInstance) {
            return yield* Effect.fail(
              new OAuthProviderError({
                message: `Provider ${provider} not found`,
                provider,
              }),
            );
          }

          // Exchange code for tokens
          const tokens = yield* providerInstance.exchangeCode(code, stateEntry.codeVerifier);

          // Get user info
          const userInfo = yield* providerInstance.getUserInfo(tokens.access_token);

          // Clean up state
          yield* stateStore.delete(state);

          // Check if this OAuth account is already linked to another user
          const existingAccount = yield* accountStore.get(provider, userInfo.id);

          if (existingAccount && existingAccount.userId !== userId) {
            return yield* Effect.fail(
              new AuthError({
                message: `This ${provider} account is already linked to another user`,
              }),
            );
          }

          // Create or update the account linked to this user
          const account: OAuthAccount = {
            id: existingAccount?.id ?? crypto.randomBytes(16).toString("hex"),
            userId,
            provider,
            providerId: userInfo.id,
            ...(userInfo.email && { email: userInfo.email }),
            ...(userInfo.name && { name: userInfo.name }),
            ...(userInfo.picture && { picture: userInfo.picture }),
            accessToken: tokens.access_token,
            ...(tokens.refresh_token && { refreshToken: tokens.refresh_token }),
            ...(tokens.expires_in && {
              expiresAt: Date.now() + tokens.expires_in * 1000,
            }),
            createdAt: existingAccount?.createdAt ?? Date.now(),
            updatedAt: Date.now(),
          };

          if (existingAccount) {
            yield* accountStore.update(account);
          } else {
            yield* accountStore.create(account);
          }

          return account;
        }),

      unlinkAccount: (userId, provider) =>
        Effect.gen(function* () {
          const accountStore = yield* OAuthAccountStoreTag;
          const accounts = yield* accountStore.getByUserId(userId);
          const account = accounts.find((a) => a.provider === provider);

          if (!account) {
            return yield* Effect.fail(
              new AuthError({
                message: `No ${provider} account linked to user ${userId}`,
              }),
            );
          }

          yield* accountStore.delete(provider, account.providerId);
        }),

      refreshAccessToken: (userId, provider) =>
        Effect.gen(function* () {
          const accountStore = yield* OAuthAccountStoreTag;
          const accounts = yield* accountStore.getByUserId(userId);
          const account = accounts.find((a) => a.provider === provider);

          if (!account || !account.refreshToken) {
            return yield* Effect.fail(
              new AuthError({
                message: `No refresh token available for ${provider}`,
              }),
            );
          }

          const providerInstance = providers[provider];
          if (!providerInstance) {
            return yield* Effect.fail(
              new OAuthProviderError({
                message: `Provider ${provider} not found`,
                provider,
              }),
            );
          }

          // Exchange refresh token for new access token
          const params = new URLSearchParams({
            client_id: providerInstance.config.clientId,
            client_secret: providerInstance.config.clientSecret,
            grant_type: "refresh_token",
            refresh_token: account.refreshToken,
          });

          const response = yield* Effect.tryPromise({
            try: () =>
              fetch(providerInstance.config.tokenEndpoint, {
                method: "POST",
                headers: {
                  "Content-Type": "application/x-www-form-urlencoded",
                },
                body: params.toString(),
              }),
            catch: (cause) =>
              new OAuthProviderError({
                message: `Failed to refresh token for ${provider}`,
                provider,
                cause,
              }),
          });

          if (!response.ok) {
            const errorText = yield* Effect.promise(() => response.text());
            return yield* Effect.fail(
              new OAuthProviderError({
                message: `Token refresh failed: ${errorText}`,
                provider,
              }),
            );
          }

          const data = (yield* Effect.promise(() => response.json())) as OAuthTokenResponse;

          // Update account with new tokens
          const updatedAccount: OAuthAccount = {
            ...account,
            accessToken: data.access_token,
            ...(data.refresh_token && { refreshToken: data.refresh_token }),
            ...(data.expires_in && {
              expiresAt: Date.now() + data.expires_in * 1000,
            }),
            updatedAt: Date.now(),
          };

          yield* accountStore.update(updatedAccount);

          return data.access_token;
        }),
    }),
  );

export const OAuthServiceLayer = (providers: Record<string, OAuthProvider>) =>
  Layer.effect(OAuthServiceTag, makeOAuthService(providers));

/**
 * Pre-built OAuth providers
 */

export const GoogleProvider = (config: {
  clientId: string;
  clientSecret: string;
  redirectUri: string;
}): OAuthProvider =>
  makeOAuthProvider(
    "google",
    {
      ...config,
      authorizationEndpoint: "https://accounts.google.com/o/oauth2/v2/auth",
      tokenEndpoint: "https://oauth2.googleapis.com/token",
      userInfoEndpoint: "https://www.googleapis.com/oauth2/v2/userinfo",
      scopes: ["openid", "email", "profile"],
    },
    true, // Use PKCE
  );

export const GitHubProvider = (config: {
  clientId: string;
  clientSecret: string;
  redirectUri: string;
}): OAuthProvider =>
  makeOAuthProvider(
    "github",
    {
      ...config,
      authorizationEndpoint: "https://github.com/login/oauth/authorize",
      tokenEndpoint: "https://github.com/login/oauth/access_token",
      userInfoEndpoint: "https://api.github.com/user",
      scopes: ["user:email"],
    },
    false, // GitHub doesn't support PKCE yet
  );

export const DiscordProvider = (config: {
  clientId: string;
  clientSecret: string;
  redirectUri: string;
}): OAuthProvider =>
  makeOAuthProvider(
    "discord",
    {
      ...config,
      authorizationEndpoint: "https://discord.com/api/oauth2/authorize",
      tokenEndpoint: "https://discord.com/api/oauth2/token",
      userInfoEndpoint: "https://discord.com/api/users/@me",
      scopes: ["identify", "email"],
    },
    true, // Use PKCE
  );

export const MicrosoftProvider = (config: {
  clientId: string;
  clientSecret: string;
  redirectUri: string;
  tenant?: string;
}): OAuthProvider =>
  makeOAuthProvider(
    "microsoft",
    {
      ...config,
      authorizationEndpoint: `https://login.microsoftonline.com/${config.tenant ?? "common"}/oauth2/v2.0/authorize`,
      tokenEndpoint: `https://login.microsoftonline.com/${config.tenant ?? "common"}/oauth2/v2.0/token`,
      userInfoEndpoint: "https://graph.microsoft.com/v1.0/me",
      scopes: ["openid", "email", "profile"],
    },
    true, // Use PKCE
  );
