# effect-auth

A generic authentication and authorization library for [Effect](https://effect.website/), following best practices from [Lucia](https://lucia-auth.com/), [Copenhagen](https://lucia-auth.com/copenhagen), [Oslo](https://github.com/pilcrowonpaper/oslo), and [BetterAuth](https://www.better-auth.com/) projects.

effect-auth is batteries-included: a headless core, plus an optional HTTP API, a typed client, framework bindings and protocol servers — each opt-in. What that means, and how this library relates to `effect-jsonapi` and `legation`, is stated once in [the three-library boundary](./docs/BOUNDARY.md).

## Features

- 🔐 **Generic and Flexible**: Effect-native services and layers — provide only the features you need, swap any implementation
- 🔒 **Secure by Default**: Following industry best practices for password hashing and session management
- 🎯 **Type-Safe**: Full TypeScript support with comprehensive type inference
- 🧩 **Composable**: Use Effect's powerful composition capabilities
- 🔄 **Bring Your Own Storage**: Implement storage adapters for any database or backend
- 📦 **Zero Lock-in**: No vendor lock-in, works with any storage backend
- 🔑 **Multi-Factor Authentication**: TOTP enrollment with backup codes, integrated into sign-in (RFC 6238/4226 primitives included)
- 🌐 **OAuth 2.0 / Social Login**: Pre-built providers for Google, GitHub, Discord, Microsoft with PKCE and a complete sign-in flow (user creation, verified-email account linking, sessions)
- ✉️ **Email Verification & Password Reset**: Secure token-based flows with anti-enumeration behavior
- 🧾 **Account Management**: Verification-gated email change and self-service account deletion (single-use tokens, session revocation, `beforeDelete` cleanup hook)
- 🪄 **Magic Link & Email OTP**: Passwordless sign-in via one-time links or numeric codes
- 📱 **Phone (SMS) OTP**: Sign-in and phone-number verification via SMS one-time codes (`attributes.phoneNumber`, pluggable E.164 normalizer)
- 📺 **Device Authorization Grant**: RFC 8628 `device_code`/`user_code` flow for CLIs and TVs (`POST /device/code` → approve → `POST /device/token`)
- 👤 **Anonymous Auth**: Guest sessions (`POST /sign-in/anonymous`) with account linking on sign-up (`isAnonymousUser` helper, `linkAccount` migration callback)
- 🪪 **Username Auth**: Sign in with a username + password (`POST /sign-in/username`), case-insensitive uniqueness, honouring the multi-factor gate
- 🛡️ **Rate Limiting**: Built-in rate limiting with configurable presets, an optional `effect/unstable/persistence` backend (in-memory or Redis) via `rateLimiterPersistenceLayer`, and an `AccountLockoutPlugin` (OWASP-style lockout after N failed sign-ins)
- 🚫 **Abuse Protection**: Captcha verification (Turnstile/reCAPTCHA/hCaptcha) and Have-I-Been-Pwned compromised-password checks as composable hooks plugins
- 🔓 **WebAuthn / Passkeys**: Passwordless authentication with FIDO2 compliance
- 🏢 **Organizations & Admin**: Multi-tenant organizations (members with deactivation, invitations, roles, per-org default role, verified email domains with opt-in JIT provisioning) and admin tooling (ban, impersonate)
- 🗝️ **API Keys & JWT**: Hashed API keys with permissions/quotas; ES256/EdDSA JWTs with JWKS
- 🌍 **HTTP Protocol**: A typed `effect/unstable/httpapi` contract serving the whole surface as a mountable Web handler with a derived typed client, session cookies, and trusted-origin CSRF protection
- 📖 **OpenAPI Document + Reference UI**: Derive an OpenAPI 3.1 spec from the HTTP contract (`Http.getOpenApiSpec()`) and optionally serve it plus a Scalar reference page via `Http.make({ docs: true })`
- 🍪 **Session Cookie Cache**: Optional HMAC-signed session-data cookie (`cookie.cache`) that serves authenticated requests without a session-store read for a short window
- 🏛️ **Enterprise SSO**: OIDC relying party with per-organization connections, email-domain routing, first-login provisioning, and just-in-time membership from verified organization domains
- 🪞 **OIDC Provider**: Act as an OpenID Connect identity provider — client registry, authorization-code flow with PKCE, consent, opaque access/refresh tokens, id_tokens on a shared JWKS, and discovery metadata
- 🔌 **MCP / dynamic client registration**: RFC 7591 self-registration (with RFC 7592 management) and RFC 8414 authorization-server metadata, so MCP clients can register and sign in unattended — see the [MCP provider guide](./docs/guides/mcp-provider.md)
- 🅶 **Google One Tap**: Verify the One Tap credential against Google's JWKS and sign in by verified email
- 🧠 **Last Login Method**: A hooks plugin + non-httpOnly cookie hint so login pages can highlight the user's previous sign-in method
- 👥 **Multi-Session**: Several signed-in accounts per browser with list/switch/revoke endpoints

## Packages

| Package                               | Purpose                                                        |
| ------------------------------------- | -------------------------------------------------------------- |
| `@thomasfosterau/effect-auth`         | The core library: every module above, `effect` as the only dep |
| `@thomasfosterau/effect-auth-client`  | Typed browser client + observable session store                |
| `@thomasfosterau/effect-auth-react`   | React hooks and form components over the browser client        |
| `@thomasfosterau/effect-auth-svelte`  | Svelte stores and form components over the browser client      |
| `@thomasfosterau/effect-auth-vue`     | Vue composables and form components over the browser client    |
| `@thomasfosterau/effect-auth-solid`   | Solid primitives and form components over the browser client   |
| `@thomasfosterau/effect-auth-sql`     | Driver-agnostic SQL storage layers (`effect/unstable/sql`)     |
| `@thomasfosterau/effect-auth-alchemy` | Alchemy v2 `AuthSchema` resource + D1-backed storage layers    |
| `@thomasfosterau/effect-auth-argon2`  | Argon2id `PasswordHasher` on WASM (`hash-wasm`)                |

## Installation

```bash
pnpm add @thomasfosterau/effect-auth effect
```

## Core Concepts

This library follows best practices from multiple authentication frameworks:

- **Sessions**: Secure session management with automatic expiration and renewal (Lucia/Copenhagen)
- **Password Hashing**: PBKDF2-SHA256 with recommended iterations (600,000+) (Oslo/OWASP)
- **Multi-Factor Authentication**: TOTP and HOTP second-factor verification (RFC 6238/4226)
- **OAuth 2.0**: Social login with major providers (BetterAuth-inspired)
- **Email Verification**: Secure verification flows with rate limiting (BetterAuth-inspired)
- **Rate Limiting**: Protection against brute force attacks (BetterAuth-inspired)
- **Services & Layers**: Every feature is an Effect `Context.Service` provided via `X.layer(config)` — swap or extend any part
- **Authorization**: Flexible permission checking and role-based access control

## Quick Start

### 1. Implement Storage Adapters

First, implement the storage interfaces for your database:

```typescript
import { Effect } from "effect";
import * as Auth from "@thomasfosterau/effect-auth";

// Implement session storage (e.g., Redis, PostgreSQL, etc.). Stores are
// "dumb persistence" — lookups return `null` on a miss; the service converts
// that into a typed `SessionNotFoundError`/`UserNotFoundError`.
const sessionStore: typeof Auth.SessionStore.Service = {
  create: (session) => Effect.succeed(session), // Your implementation
  get: (sessionId) => Effect.succeed(null), // Look up by hash; null if not found
  update: (session) => Effect.succeed(session),
  delete: (sessionId) => Effect.void,
  deleteByUserId: (userId) => Effect.void,
  listByUserId: (userId) => Effect.succeed([]),
};

// Implement user storage. Users carry first-class identity fields
// (email, emailVerified, name, image, createdAt, updatedAt) plus an
// `attributes` bag for app-specific data.
const userStore: typeof Auth.UserStore.Service = {
  get: (userId) => Effect.succeed(null), // Look up by id; null if not found
};
```

### 2. Create Session Manager

Every service class exposes a static `layer` — the canonical way to provide it:

```typescript
import { Effect, Layer } from "effect";
import * as Auth from "@thomasfosterau/effect-auth";

const sessionConfig: Auth.SessionConfig = {
  sessionExpiresIn: {
    activePeriod: 1000 * 60 * 60 * 24 * 30, // 30 days
    idlePeriod: 1000 * 60 * 60 * 24 * 14, // 14 days
  },
};

const layer = Auth.SessionService.layer(sessionConfig).pipe(
  Layer.provideMerge(
    Layer.mergeAll(
      Layer.succeed(Auth.SessionStore)(sessionStore),
      Layer.succeed(Auth.UserStore)(userStore),
      Auth.Hooks.Default, // no-op hooks; register plugins here instead as needed
    ),
  ),
);

const program = Effect.gen(function* () {
  const sessions = yield* Auth.SessionService;

  // Create a session
  const session = yield* sessions.createSession("user-123", {
    ip: "127.0.0.1",
  });

  // Validate session
  const { session: validSession, user } = yield* sessions.validateSession(session.id);

  return { session: validSession, user };
});

const result = await Effect.runPromise(Effect.provide(program, layer));
```

### 3. Use Password Hashing

```typescript
import { Effect } from "effect";
import * as Auth from "@thomasfosterau/effect-auth";

const program = Effect.gen(function* () {
  const hasher = yield* Auth.Password.PasswordHasher;

  // Hash a password
  const hashed = yield* hasher.hash("mySecurePassword");

  // Verify a password
  const isValid = yield* hasher.verify("mySecurePassword", hashed.hash);

  return isValid;
});

// Run with the default hasher
const isValid = await Effect.runPromise(
  Effect.provide(program, Auth.Password.PasswordHasher.layer()),
);
```

### 4. Compose custom layers with the low-level constructors

Most services expose their `make(config)` constructor from the module's own
file for embedding in your own layers when the static `X.layer(config)` isn't
flexible enough. `SessionService` is one of the few that also re-exposes it as
a static, so it can be shown without a deep import:

```typescript
import { Effect, Layer } from "effect";
import { SessionService } from "@thomasfosterau/effect-auth";

const customSessionLayer = Layer.effect(
  SessionService,
  Effect.gen(function* () {
    // ...acquire resources, read config, etc.
    return yield* SessionService.make(sessionConfig);
  }),
);
```

## Authorization

Implement role-based access control:

```typescript
import { Effect, Layer } from "effect";
import * as Auth from "@thomasfosterau/effect-auth";

// Implement your role store
const roleStore: typeof Auth.RoleStore.Service = {
  getUserRoles: (userId) => Effect.succeed(["admin", "user"]),
  getRolePermissions: (role) =>
    Effect.succeed([
      { resource: "posts", action: "create" },
      { resource: "posts", action: "read" },
    ]),
};

// `AuthorizationPolicy` only exposes `.layer()` (its raw `make` isn't
// re-exported from the root barrel), so provide it as a Layer.
const layer = Auth.AuthorizationPolicy.layer().pipe(
  Layer.provide(Layer.succeed(Auth.RoleStore)(roleStore)),
);

const program = Effect.gen(function* () {
  const policy = yield* Auth.AuthorizationPolicy;

  // Check permission
  const canCreate = yield* policy.checkPermission("user-123", "posts", "create");

  // Or require permission (throws if denied)
  yield* Auth.requirePermission("user-123", "posts", "create");
});

const result = await Effect.runPromise(Effect.provide(program, layer));
```

## Multi-Factor Authentication (TOTP/HOTP)

Implement multi-factor authentication using Time-based One-Time Passwords (TOTP, RFC 6238) or HMAC-based One-Time Passwords (HOTP, RFC 4226):

### TOTP (Time-based)

```typescript
import { Crypto, Effect, Layer } from "effect";
import * as Auth from "@thomasfosterau/effect-auth";

// `generateBase32Secret`/`generateSecret` take the `Crypto` service directly
// (instead of reaching for `node:crypto`); build one from the platform's Web
// Crypto API (`effect-auth`'s own layer for this is internal-only).
const CryptoLive = Layer.succeed(
  Crypto.Crypto,
  Crypto.make({
    randomBytes: (size) => globalThis.crypto.getRandomValues(new Uint8Array(size)),
    digest: (algorithm, data) =>
      Effect.promise(() => globalThis.crypto.subtle.digest(algorithm, data)).pipe(
        Effect.map((buf) => new Uint8Array(buf)),
      ),
  }),
);

const program = Effect.gen(function* () {
  const crypto = yield* Crypto.Crypto;

  // Generate a secret for the user
  const secret = yield* Auth.MultiFactor.generateBase32Secret(crypto, 20);

  // Generate a QR code URI for the user to scan
  const uri = Auth.MultiFactor.generateOtpUri({
    type: "totp",
    label: "user@example.com",
    issuer: "MyApp",
    secret,
  });

  // Display QR code to user (use a QR code library to encode the URI)
  console.log("Scan this URI with your authenticator app:", uri);

  // When the user submits a token, verify it
  const userToken = "123456"; // From user input
  const isValid = yield* Auth.MultiFactor.verifyTotp(userToken, secret);

  if (isValid) {
    // Token is valid, proceed with authentication
    return { success: true };
  } else {
    // Token is invalid
    return { success: false };
  }
});

await Effect.runPromise(Effect.provide(program, CryptoLive));
```

### HOTP (Counter-based)

```typescript
import { Crypto, Effect } from "effect";
import * as Auth from "@thomasfosterau/effect-auth";

const program = Effect.gen(function* () {
  const crypto = yield* Crypto.Crypto;

  // Generate a secret for the user
  const secret = yield* Auth.MultiFactor.generateBase32Secret(crypto, 20);

  // Store initial counter (typically 0) for the user
  let counter = 0;

  // Generate a QR code URI
  const uri = Auth.MultiFactor.generateOtpUri({
    type: "hotp",
    label: "user@example.com",
    issuer: "MyApp",
    secret,
    counter,
  });

  // Display QR code to user
  console.log("Scan this URI with your authenticator app:", uri);

  // When the user submits a token, verify it
  const userToken = "123456"; // From user input
  const isValid = yield* Auth.MultiFactor.verifyHotp(userToken, secret, counter);

  if (isValid) {
    // Token is valid, increment counter for next use
    counter++;
    // Store updated counter in database
    return { success: true, nextCounter: counter };
  } else {
    // Token is invalid
    return { success: false };
  }
});

// `program` requires `Crypto.Crypto` in context; see the `CryptoLive` layer
// in the TOTP example above.
await Effect.runPromise(Effect.provide(program, CryptoLive));
```

### Custom Configuration

Both TOTP and HOTP support custom configurations:

```typescript
// TOTP with custom settings
const totpConfig: Auth.MultiFactor.TotpConfig = {
  period: 60, // 60-second time window (default: 30)
  digits: 8, // 8-digit codes (default: 6)
  algorithm: "sha256", // Use SHA-256 (default: "sha1")
  window: 2, // Accept tokens from ±2 time steps (default: 1)
};

const token = yield * Auth.MultiFactor.generateTotp(secret, totpConfig);
const isValid = yield * Auth.MultiFactor.verifyTotp(token, secret, totpConfig);

// HOTP with custom settings
const hotpConfig: Auth.MultiFactor.HotpConfig = {
  digits: 8, // 8-digit codes (default: 6)
  algorithm: "sha512", // Use SHA-512 (default: "sha1")
};

const hotpToken = yield * Auth.MultiFactor.generateHotp(secret, counter, hotpConfig);
```

## WebAuthn / Passkeys

Implement passwordless authentication using WebAuthn (Passkeys):

```typescript
import { Effect, Layer } from "effect";
import * as Auth from "@thomasfosterau/effect-auth";

// Implement challenge store (temporary storage for challenges). Stores are
// "dumb persistence" — lookups return `null` on a miss; the service converts
// that into a typed `ChallengeNotFoundError`/`CredentialNotFoundError`.
const challengeStore: typeof Auth.MultiFactor.ChallengeStore.Service = {
  create: (challenge) => Effect.succeed(challenge), // Store in Redis/memory
  get: (challenge) => Effect.succeed(null), // null if not found
  delete: (challenge) => Effect.void,
};

// Implement credential store (persistent storage for passkeys)
const credentialStore: typeof Auth.MultiFactor.CredentialStore.Service = {
  create: (credential) => Effect.succeed(credential), // Store in database
  get: (credentialId) => Effect.succeed(null), // null if not found
  // Resolve by the raw credential id; used on the discoverable/usernameless login path.
  getByCredentialId: (credentialId) => Effect.succeed(null), // null if not found
  update: (credential) => Effect.succeed(credential),
  delete: (credentialId) => Effect.void,
  listByUserId: (userId) => Effect.succeed([]), // Return all user's credentials
};

const webAuthnConfig: Auth.MultiFactor.WebAuthnConfig = {
  relyingPartyId: "example.com",
  relyingPartyName: "Example Corp",
  expectedOrigin: "https://example.com",
  challengeExpiresIn: 5 * 60 * 1000, // 5 minutes
};

// `WebAuthnService` only exposes `.layer()` (its raw `make` isn't re-exported
// from the package root), so provide it as a Layer.
const WebAuthnLive = Auth.MultiFactor.WebAuthnService.layer(webAuthnConfig).pipe(
  Layer.provide(
    Layer.mergeAll(
      Layer.succeed(Auth.MultiFactor.ChallengeStore)(challengeStore),
      Layer.succeed(Auth.MultiFactor.CredentialStore)(credentialStore),
    ),
  ),
);

// Registration flow
const registerPasskey = Effect.gen(function* () {
  const service = yield* Auth.MultiFactor.WebAuthnService;

  // Step 1: Generate challenge
  const { challenge } = yield* service.generateRegistrationChallenge({
    id: "user-123",
    name: "user@example.com",
    displayName: "User Name",
  });

  // Send challenge to client, client creates credential
  // Client returns: credentialId, attestationObject, clientDataJSON

  // Step 2: Verify registration response
  const result = yield* service.verifyRegistration(challenge, {
    credentialId: clientCredentialId,
    attestationObject: clientAttestationObject,
    clientDataJSON: clientDataJSON,
  });

  // Credential is now stored and ready for authentication
  return result.credential;
});

// Authentication flow
const authenticateWithPasskey = Effect.gen(function* () {
  const service = yield* Auth.MultiFactor.WebAuthnService;

  // Step 1: Generate challenge
  const { challenge } = yield* service.generateAuthenticationChallenge("user-123");

  // Send challenge to client, client signs with passkey
  // Client returns: credentialId, authenticatorData, clientDataJSON, signature

  // Step 2: Verify authentication response
  const result = yield* service.verifyAuthentication(challenge, {
    credentialId: clientCredentialId,
    authenticatorData: clientAuthenticatorData,
    clientDataJSON: clientDataJSON,
    signature: clientSignature,
  });

  // User is authenticated, create session
  const sessions = yield* Auth.SessionService.make(sessionConfig);
  const session = yield* sessions.createSession(result.credential.userId);

  return session;
});

await Effect.runPromise(Effect.provide(registerPasskey, WebAuthnLive));
```

## OAuth 2.0 / Social Login

Authenticate users with OAuth2 providers like Google, GitHub, Discord, and Microsoft:

```typescript
import { Effect, Context } from "effect";
import * as Auth from "@thomasfosterau/effect-auth";

// Implement OAuth state store (temporary, Redis/memory recommended)
const oauthStateStore: typeof Auth.OAuth.OAuthStateStore.Service = {
  create: (state) => Effect.succeed(state), // Store in Redis with 10-minute TTL
  get: (stateStr) => Effect.succeed(null), // null when unknown/expired-and-purged
  delete: (stateStr) => Effect.void,
};

// Implement OAuth account store (persistent, database)
const oauthAccountStore: typeof Auth.OAuth.OAuthAccountStore.Service = {
  create: (account) => Effect.succeed(account), // Store in database
  get: (provider, providerId) => Effect.succeed(null), // Return account or null
  getByUserId: (userId) => Effect.succeed([]), // Return all user's OAuth accounts
  update: (account) => Effect.succeed(account),
  linkToUser: (userId, account) => Effect.void,
  unlinkFromUser: (userId, provider) => Effect.void,
  delete: (provider, providerId) => Effect.void,
};

// Implement the OAuth-side user store (resolves/creates users during sign-in;
// required by `OAuth.make` even if you only call `handleCallback` yourself)
const oauthUserStore: typeof Auth.OAuth.OAuthUserStore.Service = {
  getUser: (userId) => Effect.fail(new Auth.UserNotFoundError({ message: "Not found", userId })),
  getUserByEmail: (email) => Effect.succeed(null), // Look up by email in your database
  createUser: (input) =>
    Effect.succeed({
      id: "user-123", // Assign a real id when persisting
      email: input.email,
      emailVerified: input.emailVerified,
      createdAt: new Date(),
      updatedAt: new Date(),
      attributes: {},
    }),
};

// Configure OAuth providers
const providers = {
  google: Auth.OAuth.GoogleProvider({
    clientId: process.env.GOOGLE_CLIENT_ID!,
    clientSecret: process.env.GOOGLE_CLIENT_SECRET!,
    redirectUri: "https://example.com/auth/google/callback",
  }),
  github: Auth.OAuth.GitHubProvider({
    clientId: process.env.GITHUB_CLIENT_ID!,
    clientSecret: process.env.GITHUB_CLIENT_SECRET!,
    redirectUri: "https://example.com/auth/github/callback",
  }),
  discord: Auth.OAuth.DiscordProvider({
    clientId: process.env.DISCORD_CLIENT_ID!,
    clientSecret: process.env.DISCORD_CLIENT_SECRET!,
    redirectUri: "https://example.com/auth/discord/callback",
  }),
  microsoft: Auth.OAuth.MicrosoftProvider({
    clientId: process.env.MICROSOFT_CLIENT_ID!,
    clientSecret: process.env.MICROSOFT_CLIENT_SECRET!,
    redirectUri: "https://example.com/auth/microsoft/callback",
  }),
};

// Create OAuth service
const oauthService = Effect.gen(function* () {
  return yield* Auth.OAuth.make(providers);
});

// Step 1: Generate authorization URL (initiate OAuth flow)
const initiateOAuth = Effect.gen(function* () {
  const service = yield* oauthService;

  const { url, state } = yield* service.generateAuthorizationUrl("google", {
    scopes: ["email", "profile"],
    returnTo: "/dashboard", // Optional redirect after auth
  });

  // Redirect user to this URL
  console.log("Redirect to:", url);
  return { url, state };
});

// Step 2: Handle OAuth callback
const handleOAuthCallback = (code: string, state: string) =>
  Effect.gen(function* () {
    const service = yield* oauthService;

    // Verify state and exchange code for tokens
    const result = yield* service.handleCallback(state, code);

    if (result.isNewUser) {
      // New user - create account
      console.log("New user from OAuth:", result.account.email);
      // Create user in your database
      // Link OAuth account to new user
    } else {
      // Existing user - log them in
      console.log("Existing user:", result.account.userId);
    }

    // Create session
    const sessions = yield* Auth.SessionService.make(sessionConfig);
    const session = yield* sessions.createSession(result.account.userId);

    return { session, account: result.account };
  });

// Link additional OAuth account to existing user
const linkOAuthAccount = (userId: string, provider: string, code: string, state: string) =>
  Effect.gen(function* () {
    const service = yield* oauthService;

    const account = yield* service.linkAccount(userId, provider, code, state);

    console.log(`Linked ${provider} account to user ${userId}`);
    return account;
  });

// Refresh OAuth access token
const refreshToken = (userId: string, provider: string) =>
  Effect.gen(function* () {
    const service = yield* oauthService;

    const newAccessToken = yield* service.refreshAccessToken(userId, provider);

    return newAccessToken;
  });

// Provide dependencies and run
const oauthDependencies = Context.mergeAll(
  Context.make(Auth.OAuth.OAuthStateStore, oauthStateStore),
  Context.make(Auth.OAuth.OAuthAccountStore, oauthAccountStore),
  Context.make(Auth.OAuth.OAuthUserStore, oauthUserStore),
);

await Effect.runPromise(Effect.provide(initiateOAuth, oauthDependencies));
```

## Email Verification

Implement secure email verification flows:

```typescript
import { Effect, Layer } from "effect";
import * as Auth from "@thomasfosterau/effect-auth";

// Implement email verification store
const emailVerificationStore: typeof Auth.Email.EmailVerificationStore.Service = {
  create: (verification) => Effect.succeed(verification), // Store in database
  get: (token) => Effect.succeed(null), // Return verification or null
  delete: (token) => Effect.void,
  deleteByUserId: (userId) => Effect.void,
};

// `Email.EmailVerificationService` only exposes `.layer()` (its raw `make`
// isn't re-exported from the `email` barrel), so provide it as a Layer.
const EmailVerificationLive = Auth.Email.EmailVerificationService.layer({
  expiresIn: 24 * 60 * 60 * 1000, // 24 hours
  sendEmail: (to, token) =>
    Effect.tryPromise({
      try: () =>
        emailClient.send({
          to,
          subject: "Verify your email",
          html: `Click here to verify: https://example.com/verify?token=${token}`,
        }),
      catch: (error) =>
        new Auth.EmailVerificationError({
          message: "Failed to send email",
          cause: error,
        }),
    }),
}).pipe(
  Layer.provide(
    Layer.mergeAll(
      Layer.succeed(Auth.Email.EmailVerificationStore)(emailVerificationStore),
      Auth.Hooks.Default, // no-op hooks; register plugins here instead as needed
    ),
  ),
);

// Send verification email
const sendVerification = (userId: string, email: string) =>
  Effect.gen(function* () {
    const service = yield* Auth.Email.EmailVerificationService;

    const { token, expiresAt } = yield* service.createVerification(userId, email);

    console.log(`Verification email sent to ${email}`);
    return { token, expiresAt };
  });

// Verify token
const verifyEmail = (token: string) =>
  Effect.gen(function* () {
    const service = yield* Auth.Email.EmailVerificationService;

    const result = yield* service.verifyToken(token);

    if (result.verified) {
      console.log(`Email ${result.email} verified for user ${result.userId}`);
      // Update user's email verification status in database
    }

    return result;
  });

await Effect.runPromise(Effect.provide(verifyEmail("token123"), EmailVerificationLive));
```

## Rate Limiting

Protect your authentication endpoints with rate limiting:

```typescript
import { Effect, Layer } from "effect";
import * as Auth from "@thomasfosterau/effect-auth";

// Implement rate limit store (Redis recommended for distributed systems)
const rateLimitStore: typeof Auth.RateLimitStore.Service = {
  get: (key) => Effect.succeed(null), // Return entry or null from Redis
  set: (key, entry, ttl) => Effect.void, // Store in Redis with TTL
  increment: (key, ttl) => Effect.succeed(1), // Atomic increment in Redis
  delete: (key) => Effect.void,
};

// `RateLimiter` only exposes `.layer()` (its raw `make` isn't re-exported
// from the package root), so provide it as a Layer.
const RateLimiterLive = Auth.RateLimiter.layer().pipe(
  Layer.provide(Layer.succeed(Auth.RateLimitStore)(rateLimitStore)),
);

// Apply rate limiting to login endpoint
const login = (email: string, password: string, ip: string) =>
  Effect.gen(function* () {
    const limiter = yield* Auth.RateLimiter;

    // Rate limit by IP address
    yield* limiter.consumeToken(`login:${ip}`, Auth.RateLimitPresets.login);

    // Proceed with login...
    const hasher = yield* Auth.Password.PasswordHasher;
    const userStore = yield* Auth.UserStore;
    const passwordStore = yield* Auth.Email.EmailPasswordStore;

    const user = yield* userStore.get(email);
    const hash = yield* passwordStore.getPasswordHash(user.id);
    const isValid = yield* hasher.verify(password, hash);

    if (!isValid) {
      return yield* Effect.fail(
        new Auth.InvalidCredentialsError({ message: "Invalid credentials" }),
      );
    }

    // Create session
    const sessions = yield* Auth.SessionService.make(sessionConfig);
    const session = yield* sessions.createSession(user.id);

    return session;
  });

// Custom rate limit configuration
const customRateLimit: Auth.RateLimitConfig = {
  maxRequests: 10,
  windowMs: 60 * 1000, // 1 minute
  blockDurationMs: 5 * 60 * 1000, // 5 minute block
};

// Use pre-configured rate limits
const rateLimits = {
  login: Auth.RateLimitPresets.login, // 5 per 15 min
  passwordReset: Auth.RateLimitPresets.passwordReset, // 3 per hour
  emailVerification: Auth.RateLimitPresets.emailVerification, // 3 per 10 min
  registration: Auth.RateLimitPresets.registration, // 3 per hour
  oauth: Auth.RateLimitPresets.oauth, // 10 per 5 min
  totpVerification: Auth.RateLimitPresets.totpVerification, // 5 per 5 min
};

await Effect.runPromise(
  Effect.provide(login("user@example.com", "password", "192.168.1.1"), RateLimiterLive),
);
```

## Abuse Protection (captcha + Have I Been Pwned)

`CaptchaPlugin` and `HaveIBeenPwnedPlugin` are hooks plugins (`before*`
transforms) composed with `composePlugins`. Both use `effect/unstable/http`'s
`HttpClient`, so provide `FetchHttpClient.layer` (or a stub in tests).

```typescript
import { Effect, Layer, Redacted } from "effect";
import { FetchHttpClient } from "effect/unstable/http";
import * as Auth from "@thomasfosterau/effect-auth";

// Reject compromised passwords (k-anonymity range query) and require a captcha
// token on sign-up/sign-in. Array order is execution order.
const plugins = Auth.composePlugins([
  Auth.Password.HaveIBeenPwnedPlugin({ threshold: 1 }),
  Auth.Plugins.CaptchaPlugin({
    provider: "cloudflare-turnstile",
    secretKey: Redacted.make(process.env.TURNSTILE_SECRET!),
    endpoints: ["signUp", "signIn"],
  }),
]);

// The plugin stack requires `Hooks.Default` and an `HttpClient`.
const Hooks = plugins.pipe(Layer.provide(Auth.Hooks.Default), Layer.provide(FetchHttpClient.layer));
```

The captcha token is read from the optional `captchaToken` field on the
sign-up/sign-in inputs (wired through the `SignUpPayload`/`SignInPayload` HTTP
schemas). HIBP fails open on API errors by default (`failClosed: false`).

## API Reference

### Types

Flat root exports (`Auth.X`) unless noted:

- `User`: Represents a user with ID and attributes
- `Session`: Represents an active session
- `SessionWithUser`: Session combined with user data
- `SessionConfig`: Configuration for session expiration
- `HashedPassword`: Hashed password with algorithm info
- `Permission`: Permission check result
- `TotpConfig`: Configuration for TOTP generation and verification
- `HotpConfig`: Configuration for HOTP generation and verification
- `OtpUriParams`: Parameters for generating OTP URIs (for QR codes)
- `WebAuthnChallenge`: Temporary challenge for WebAuthn operations
- `WebAuthnCredential`: Stored passkey credential
- `WebAuthnConfig`: Configuration for WebAuthn service
- `WebAuthnUser`: User information for passkey registration
- `Auth.OAuth.OAuthProviderConfig`: OAuth2 provider configuration
- `Auth.OAuth.OAuthState`: OAuth state for CSRF protection
- `Auth.OAuth.OAuthAccount`: OAuth account linked to user
- `Auth.OAuth.OAuthTokenResponse`: OAuth2 token exchange response
- `Auth.OAuth.OAuthUserInfo`: User info from OAuth provider
- `Auth.Email.EmailVerification`: Email verification token data
- `Auth.Email.EmailVerificationConfig`: Email verification service configuration
- `RateLimitConfig`: Rate limiting configuration
- `RateLimitEntry`: Rate limit entry data

### Services

Flat root exports (`Auth.X`) unless noted:

- `SessionStore`: Interface for session persistence
- `UserStore`: Interface for user data retrieval
- `SessionService`: Service for managing sessions
- `Auth.Password.PasswordHasher`: Service for password hashing and verification
- `Auth.AuthorizationPolicy`: Interface for permission checking
- `Auth.RoleStore`: Interface for role-based authorization
- `ChallengeStore`: Interface for WebAuthn challenge storage
- `CredentialStore`: Interface for WebAuthn credential storage
- `WebAuthnService`: Service for passkey registration and authentication
- `Auth.OAuth.OAuthStateStore`: Interface for OAuth state storage (temporary)
- `Auth.OAuth.OAuthAccountStore`: Interface for OAuth account storage (persistent)
- `Auth.OAuth.OAuthService`: Service for OAuth2 flows
- `Auth.Email.EmailVerificationStore`: Interface for email verification storage
- `Auth.Email.EmailVerificationService`: Service for email verification
- `RateLimitStore`: Interface for rate limit storage
- `RateLimiter`: Service for rate limiting

### OAuth Functions

- `provider(name, config, usePKCE?)`: Create a custom OAuth provider
- `make(providers, options?)`: Create OAuth service with configured providers
- `GoogleProvider(config)`: Pre-built Google OAuth provider
- `GitHubProvider(config)`: Pre-built GitHub OAuth provider
- `DiscordProvider(config)`: Pre-built Discord OAuth provider
- `MicrosoftProvider(config)`: Pre-built Microsoft OAuth provider
- `generateState()`: Generate secure OAuth state parameter
- `generatePKCE()`: Generate PKCE code verifier and challenge

### Email Verification Functions

- `make(config)`: Create email verification service
- `generateVerificationToken(crypto)`: Generate secure verification token

### Rate Limiting Functions

- `make()`: Create rate limiter service
- `RateLimitPresets`: Pre-configured rate limits for common operations
  - `RateLimitPresets.login`: 5 per 15 minutes
  - `RateLimitPresets.passwordReset`: 3 per hour
  - `RateLimitPresets.emailVerification`: 3 per 10 minutes
  - `RateLimitPresets.registration`: 3 per hour
  - `RateLimitPresets.oauth`: 10 per 5 minutes
  - `RateLimitPresets.totpVerification`: 5 per 5 minutes

### OTP Functions

All OTP functions return Effect types for composability:

- `generateSecret(crypto, length?)`: Generate cryptographically secure random bytes
- `generateBase32Secret(crypto, length?)`: Generate a base32-encoded secret
- `encodeBase32(buffer)`: Encode bytes to base32 string
- `decodeBase32(base32)`: Decode base32 string to bytes
- `generateHotp(secret, counter, config?)`: Generate HOTP token
- `verifyHotp(token, secret, counter, config?)`: Verify HOTP token
- `generateTotp(secret, config?)`: Generate TOTP token
- `verifyTotp(token, secret, config?)`: Verify TOTP token
- `generateOtpUri(params)`: Generate OTP URI for QR codes

### Errors

All errors extend Effect's tagged errors:

- `AuthError`: Generic authentication error
- `InvalidCredentialsError`: Invalid credentials
- `SessionNotFoundError`: Session not found
- `SessionExpiredError`: Session has expired
- `UserNotFoundError`: User not found
- `PermissionDeniedError`: Permission denied
- `HashingError`: Password hashing error
- `ChallengeNotFoundError`: WebAuthn challenge not found
- `ChallengeExpiredError`: WebAuthn challenge expired
- `CredentialNotFoundError`: WebAuthn credential not found
- `WebAuthnVerificationError`: WebAuthn verification failed
- `OAuthStateNotFoundError`: OAuth state not found
- `OAuthStateExpiredError`: OAuth state expired
- `OAuthProviderError`: OAuth provider error
- `RateLimitError`: Rate limit exceeded
- `EmailVerificationError`: Email verification error
- `MagicLinkError`: Magic link error
- `PasswordResetError`: Password reset error

## Best Practices

### Session Management

Following Copenhagen Book guidelines:

1. Use secure, random session IDs (160+ bits entropy)
2. Implement both active and idle timeouts
3. Store minimal data in sessions
4. Rotate sessions on privilege changes
5. Use HTTP-only cookies in web applications

### Password Hashing

Following Oslo guidelines:

1. Use PBKDF2-SHA256 with 600,000+ iterations
2. Generate random salts per password
3. Use timing-safe comparisons
4. Never store plaintext passwords

### Authorization

1. Implement principle of least privilege
2. Check permissions at the application layer
3. Use explicit permission checks
4. Log authorization failures

## Security

Security is our top priority. See our [Security Policy](./docs/SECURITY.md) for:

- How to report security vulnerabilities
- Security guarantees and considerations
- Implementation requirements for secure deployments
- Best practices from OWASP, Lucia, Copenhagen Book, and Oslo

**Key Security Features:**

- ✅ PBKDF2-SHA256 with 600,000+ iterations (OWASP recommended)
- ✅ Timing-safe comparisons for all security-sensitive operations
- ✅ Cryptographically secure random generation
- ✅ Secure session management following Copenhagen Book guidelines
- ✅ Input validation and error handling

### Multi-Factor Authentication

Following RFC 6238 (TOTP) and RFC 4226 (HOTP) guidelines:

1. Generate secrets with sufficient entropy (minimum 160 bits / 20 bytes)
2. Use timing-safe comparisons when verifying tokens
3. Implement rate limiting on verification endpoints to prevent brute force
4. For TOTP, use a reasonable time window (default: ±1 step)
5. For HOTP, increment counters only after successful verification
6. Never reuse tokens within their validity window
7. Store secrets securely (encrypted at rest)
8. Use standard 6-digit codes for compatibility with authenticator apps
9. Provide backup codes for account recovery
10. Display QR codes securely over HTTPS

### WebAuthn

Following FIDO2/WebAuthn standards and Oslo guidelines:

1. Use secure random challenges (256 bits entropy)
2. Implement challenge expiration (5 minutes recommended)
3. Verify origin and relying party ID on every request
4. Use counter-based replay protection
5. Support multiple credentials per user
6. Store credentials securely with public keys only
7. Use ES256 (ECDSA with P-256) algorithm for broad compatibility

### OAuth 2.0 / Social Login

Following OAuth 2.0 and OpenID Connect standards:

1. Use PKCE (Proof Key for Code Exchange) for enhanced security
2. Implement state parameter for CSRF protection
3. Store OAuth state temporarily (10 minutes max)
4. Validate redirect URIs strictly
5. Handle token refresh for long-lived sessions
6. Support account linking for existing users
7. Rate limit OAuth flows to prevent abuse
8. Never expose client secrets in client-side code

### Email Verification

Following BetterAuth and industry best practices:

1. Use cryptographically secure tokens (256 bits entropy)
2. Set reasonable expiration times (24 hours recommended)
3. One-time use tokens only
4. Rate limit verification requests
5. Send verification emails over secure channels
6. Never include sensitive data in verification URLs
7. Implement resend functionality with rate limiting

### Rate Limiting

Following BetterAuth and OWASP guidelines:

1. Apply rate limits to all authentication endpoints
2. Use IP-based limits for anonymous operations
3. Use user-based limits for authenticated operations
4. Implement progressive delays or blocks
5. Log rate limit violations for security monitoring
6. Use distributed rate limiting for multi-server deployments
7. Configure appropriate limits per operation type

## Documentation

- [Contributing Guide](./docs/CONTRIBUTING.md) - How to contribute to this project
- [Architecture](./docs/ARCHITECTURE.md) - Architectural overview and design patterns
- [The Three-Library Boundary](./docs/BOUNDARY.md) - What effect-auth is, and how it relates to effect-jsonapi and legation
- [Architecture Decision Records](./docs/adr/README.md) - The decisions behind the design, with their supersessions
- [Bring Your Own Store](./docs/guides/byo-stores.md) - Store-contract conventions, atomicity rules, and a worked example for any database
- [MCP Provider Guide](./docs/guides/mcp-provider.md) - Dynamic client registration and PKCE auth-code for MCP clients
- [Migrating from Better Auth](./docs/guides/better-auth-migration.md) - Concept map, flow equivalents, client swap, and schema migration
- [Auth as a Separate Service](./docs/guides/split-auth-service.md) - Remote session resolution over a service binding, and the `Set-Cookie` relay
- [Security Policy](./docs/SECURITY.md) - Security best practices and vulnerability reporting
- [Better Auth Parity Plan](./docs/better-auth-parity.md) - Target architecture, roadmap, and feature parity tracking

## Contributing

Contributions are welcome! Please see our [Contributing Guide](./docs/CONTRIBUTING.md) for details.

Before contributing, please review:

- [Contributing Guide](./docs/CONTRIBUTING.md) for the development workflow
- [Security Policy](./docs/SECURITY.md) for security considerations

## License

ISC

## Acknowledgments

This library is inspired by and follows guidelines from:

- [Lucia](https://lucia-auth.com/) - Modern authentication library
- [The Copenhagen Book](https://lucia-auth.com/copenhagen) - Authentication best practices
- [Oslo](https://github.com/pilcrowonpaper/oslo) - Authentication primitives
- [BetterAuth](https://www.better-auth.com/) - Comprehensive TypeScript authentication framework
- [Effect](https://effect.website/) - Powerful TypeScript framework
- [OWASP](https://owasp.org/) - Web application security standards

Special thanks to the BetterAuth project for inspiring the OAuth2, email verification, and rate limiting implementations.
