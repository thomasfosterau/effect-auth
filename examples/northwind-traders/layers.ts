/**
 * Layer composition for the Northwind example.
 *
 * - `StoresLayer` exposes the in-memory adapters as Context tags.
 * - `ServicesLayer` builds the effect-auth services that depend on those stores.
 * - `AppLayer` wires services on top of stores and re-exports both, so callers
 *   can consume any tag (e.g. `SessionManagerTag`, `OAuthAccountStoreTag`) from
 *   a single layer.
 */

import { Effect, Layer } from "effect";
import * as Auth from "effect-auth";
import {
  emailPasswordStore,
  emailVerificationStore,
  oauthAccountStore,
  oauthStateStore,
  rateLimitStore,
  sessionStore,
  userServiceStore,
  userStore,
} from "./adapters.ts";
import { setCapturedToken } from "./domain.ts";
import { NorthwindServiceLayer } from "./northwind.ts";
import { roleStore } from "./permissions.ts";

export const sessionConfig: Auth.SessionConfig = {
  sessionExpiresIn: {
    activePeriod: 1000 * 60 * 60 * 24 * 30, // 30 days
    idlePeriod: 1000 * 60 * 60 * 24 * 14, // 14 days
  },
};

// Demo OAuth providers. Credentials are placeholders — the example only
// exercises authorization-URL generation, never the token-exchange callback.
const oauthProviders = {
  github: Auth.GitHubProvider({
    clientId: process.env["GITHUB_CLIENT_ID"] ?? "demo-github-client-id",
    clientSecret: process.env["GITHUB_CLIENT_SECRET"] ?? "demo-github-client-secret",
    redirectUri: "http://localhost:3000/auth/github/callback",
  }),
  google: Auth.GoogleProvider({
    clientId: process.env["GOOGLE_CLIENT_ID"] ?? "demo-google-client-id",
    clientSecret: process.env["GOOGLE_CLIENT_SECRET"] ?? "demo-google-client-secret",
    redirectUri: "http://localhost:3000/auth/google/callback",
  }),
};

const StoresLayer = Layer.mergeAll(
  Layer.succeed(Auth.SessionStoreTag, sessionStore),
  Layer.succeed(Auth.UserStoreTag, userStore),
  Layer.succeed(Auth.UserServiceStoreTag, userServiceStore),
  Layer.succeed(Auth.EmailPasswordStoreTag, emailPasswordStore),
  Layer.succeed(Auth.EmailVerificationStoreTag, emailVerificationStore),
  Layer.succeed(Auth.RateLimitStoreTag, rateLimitStore),
  Layer.succeed(Auth.OAuthStateStoreTag, oauthStateStore),
  Layer.succeed(Auth.OAuthAccountStoreTag, oauthAccountStore),
  Layer.succeed(Auth.RoleStoreTag, roleStore),
);

const ServicesLayer = Layer.mergeAll(
  // No-op hooks base; swap for a `composePlugins([...])` stack to install plugins.
  Auth.Hooks.Default,
  Auth.PasswordHasherLayer,
  Auth.SessionManagerLayer(sessionConfig),
  Auth.UserServiceLayer(),
  Auth.EmailVerificationServiceLayer({
    sendEmail: (_to, token) => Effect.sync(() => setCapturedToken(token)),
  }),
  Auth.AuthLifecycleServiceLayer({
    requireEmailVerification: true,
    sendOnSignUp: true,
  }),
  Auth.RateLimiterLayer(),
  Auth.AuthorizationPolicyLayer(),
  Auth.OAuthServiceLayer(oauthProviders),
);

export const AppLayer = Layer.provideMerge(
  Layer.merge(ServicesLayer, NorthwindServiceLayer),
  StoresLayer,
);
