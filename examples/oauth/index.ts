/**
 * OAuth 2.0 Social Login Example
 *
 * This example demonstrates how to implement OAuth2 authentication
 * with Google, GitHub, Discord, and Microsoft providers.
 */

import { Effect, Context } from "effect";
import * as Auth from "effect-auth";

// =============================================================================
// Storage Implementations (in-memory for demo, use Redis/DB in production)
// =============================================================================

// In-memory stores (replace with real implementations)
const oauthStates = new Map<string, Auth.OAuthState>();
const oauthAccounts = new Map<string, Auth.OAuthAccount>();

const oauthStateStore: Auth.OAuthStateStore = {
  create: (state) => {
    oauthStates.set(state.state, state);
    return Effect.succeed(state);
  },
  get: (stateStr) => {
    const state = oauthStates.get(stateStr);
    if (!state) {
      return Effect.fail(
        new Auth.OAuthStateNotFoundError({
          message: "OAuth state not found",
          state: stateStr,
        }),
      );
    }
    return Effect.succeed(state);
  },
  delete: (stateStr) => {
    oauthStates.delete(stateStr);
    return Effect.void;
  },
};

const oauthAccountStore: Auth.OAuthAccountStore = {
  create: (account) => {
    const key = `${account.provider}:${account.providerId}`;
    oauthAccounts.set(key, account);
    return Effect.succeed(account);
  },
  get: (provider, providerId) => {
    const key = `${provider}:${providerId}`;
    const account = oauthAccounts.get(key);
    return Effect.succeed(account ?? null);
  },
  getByUserId: (userId) => {
    const accounts = Array.from(oauthAccounts.values()).filter((a) => a.userId === userId);
    return Effect.succeed(accounts);
  },
  update: (account) => {
    const key = `${account.provider}:${account.providerId}`;
    oauthAccounts.set(key, account);
    return Effect.succeed(account);
  },
  linkToUser: (userId, account) => {
    const key = `${account.provider}:${account.providerId}`;
    oauthAccounts.set(key, { ...account, userId });
    return Effect.void;
  },
  unlinkFromUser: (userId, provider) => {
    const accounts = Array.from(oauthAccounts.entries()).filter(
      ([_, a]) => a.userId === userId && a.provider === provider,
    );
    accounts.forEach(([key]) => oauthAccounts.delete(key));
    return Effect.void;
  },
  delete: (provider, providerId) => {
    const key = `${provider}:${providerId}`;
    oauthAccounts.delete(key);
    return Effect.void;
  },
};

// =============================================================================
// OAuth Provider Configuration
// =============================================================================

const providers = {
  google: Auth.GoogleProvider({
    clientId: process.env.GOOGLE_CLIENT_ID ?? "your-client-id",
    clientSecret: process.env.GOOGLE_CLIENT_SECRET ?? "your-client-secret",
    redirectUri: "http://localhost:3000/auth/google/callback",
  }),
  github: Auth.GitHubProvider({
    clientId: process.env.GITHUB_CLIENT_ID ?? "your-client-id",
    clientSecret: process.env.GITHUB_CLIENT_SECRET ?? "your-client-secret",
    redirectUri: "http://localhost:3000/auth/github/callback",
  }),
  discord: Auth.DiscordProvider({
    clientId: process.env.DISCORD_CLIENT_ID ?? "your-client-id",
    clientSecret: process.env.DISCORD_CLIENT_SECRET ?? "your-client-secret",
    redirectUri: "http://localhost:3000/auth/discord/callback",
  }),
  microsoft: Auth.MicrosoftProvider({
    clientId: process.env.MICROSOFT_CLIENT_ID ?? "your-client-id",
    clientSecret: process.env.MICROSOFT_CLIENT_SECRET ?? "your-client-secret",
    redirectUri: "http://localhost:3000/auth/microsoft/callback",
  }),
};

// =============================================================================
// OAuth Service
// =============================================================================

const oauthService = Auth.makeOAuthService(providers);

// =============================================================================
// Example 1: Initiate OAuth Login
// =============================================================================

const initiateGoogleLogin = Effect.gen(function* () {
  const service = yield* oauthService;

  const { url, state } = yield* service.generateAuthorizationUrl("google", {
    scopes: ["email", "profile"],
    returnTo: "/dashboard",
  });

  console.log("\n=== Initiate Google OAuth Login ===");
  console.log("Authorization URL:", url);
  console.log("State (store this in session):", state);
  console.log("Redirect user to this URL to start OAuth flow");

  return { url, state };
});

// =============================================================================
// Example 2: Handle OAuth Callback
// =============================================================================

export const handleGoogleCallback = (code: string, state: string) =>
  Effect.gen(function* () {
    const service = yield* oauthService;

    console.log("\n=== Handle Google OAuth Callback ===");
    console.log("Code:", code);
    console.log("State:", state);

    const result = yield* service.handleCallback(state, code);

    if (result.isNewUser) {
      console.log("New user from Google!");
      console.log("Email:", result.account.email);
      console.log("Name:", result.account.name);
      console.log("Picture:", result.account.picture);
      console.log("You should create a user account in your database now.");
    } else {
      console.log("Existing user logged in");
      console.log("User ID:", result.account.userId);
    }

    return result;
  });

// =============================================================================
// Example 3: Link Additional OAuth Account
// =============================================================================

export const linkGitHubAccount = (userId: string, code: string, state: string) =>
  Effect.gen(function* () {
    const service = yield* oauthService;

    console.log("\n=== Link GitHub Account ===");
    console.log("User ID:", userId);

    const account = yield* service.linkAccount(userId, "github", code, state);

    console.log("GitHub account linked successfully!");
    console.log("Provider ID:", account.providerId);
    console.log("Email:", account.email);

    return account;
  });

// =============================================================================
// Example 4: List User's OAuth Accounts
// =============================================================================

export const listUserAccounts = (userId: string) =>
  Effect.gen(function* () {
    const accounts = yield* oauthAccountStore.getByUserId(userId);

    console.log("\n=== User's OAuth Accounts ===");
    console.log("User ID:", userId);
    accounts.forEach((account) => {
      console.log(`- ${account.provider}: ${account.email}`);
    });

    return accounts;
  });

// =============================================================================
// Example 5: Unlink OAuth Account
// =============================================================================

export const unlinkAccount = (userId: string, provider: string) =>
  Effect.gen(function* () {
    const service = yield* oauthService;

    console.log("\n=== Unlink OAuth Account ===");
    console.log("User ID:", userId);
    console.log("Provider:", provider);

    yield* service.unlinkAccount(userId, provider);

    console.log(`${provider} account unlinked successfully!`);
  });

// =============================================================================
// Example 6: Refresh Access Token
// =============================================================================

export const refreshGoogleToken = (userId: string) =>
  Effect.gen(function* () {
    const service = yield* oauthService;

    console.log("\n=== Refresh Google Access Token ===");
    console.log("User ID:", userId);

    const newAccessToken = yield* service.refreshAccessToken(userId, "google");

    console.log("New access token obtained:", newAccessToken.substring(0, 20) + "...");

    return newAccessToken;
  });

// =============================================================================
// Run Examples
// =============================================================================

const dependencies = Context.merge(
  Context.make(Auth.OAuthStateStore, oauthStateStore),
  Context.make(Auth.OAuthAccountStore, oauthAccountStore),
);

// Example: Run the OAuth flow simulation
const runExample = Effect.gen(function* () {
  console.log("=".repeat(70));
  console.log("OAuth 2.0 Social Login Example");
  console.log("=".repeat(70));

  // Step 1: Initiate login
  yield* initiateGoogleLogin;

  // Step 2: Simulate OAuth callback (in real app, this comes from provider)
  // Uncomment the examples below to run them:

  // const mockCode = "mock_authorization_code_from_google"
  // const mockState = "mock_state_from_step_1"
  // const result = yield* handleGoogleCallback(mockCode, mockState)

  // Step 3: Link additional account (example)
  // yield* linkGitHubAccount("user-123", "mock_github_code", "mock_state")

  // Step 4: List accounts
  // yield* listUserAccounts("user-123")

  // Step 5: Unlink account
  // yield* unlinkAccount("user-123", "github")

  // Step 6: Refresh token
  // yield* refreshGoogleToken("user-123")

  console.log("\n" + "=".repeat(70));
  console.log("Example completed!");
  console.log("=".repeat(70));
});

// Run the example
Effect.runPromise(Effect.provide(runExample, dependencies))
  .then(() => {
    console.log("\n✓ OAuth example completed successfully");
  })
  .catch((error) => {
    console.error("\n✗ Error:", error);
    process.exit(1);
  });
