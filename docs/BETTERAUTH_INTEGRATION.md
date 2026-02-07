# BetterAuth Integration Guide

This document details the integration of BetterAuth-inspired features into effect-auth, including architectural decisions, implementation details, and migration strategies.

## Executive Summary

**Integration Approach:** Feature-selective adoption with Effect-native implementation

BetterAuth is a comprehensive TypeScript authentication framework with excellent developer experience and broad feature coverage. Rather than wrapping or depending on BetterAuth, effect-auth adopts key architectural patterns and feature implementations from BetterAuth while maintaining its Effect-first design philosophy.

## Feature Comparison Matrix

| Feature | effect-auth (before) | BetterAuth | effect-auth (after integration) |
|---------|---------------------|------------|--------------------------------|
| Password Hashing | ✅ PBKDF2-SHA256 | ✅ Multiple algorithms | ✅ Multi-algorithm support |
| Session Management | ✅ Active/idle timeouts | ✅ Multi-session support | ✅ Enhanced with refresh tokens |
| TOTP/HOTP | ✅ RFC-compliant | ✅ Plugin-based | ✅ Native support |
| WebAuthn/Passkeys | ✅ FIDO2 compliant | ✅ Via plugin | ✅ Native support |
| OAuth2/OIDC | ❌ Not supported | ✅ 15+ providers | ✅ **NEW: Provider framework** |
| Email Verification | ❌ Not supported | ✅ Built-in flows | ✅ **NEW: Verification service** |
| Magic Links | ❌ Not supported | ✅ Passwordless flow | ✅ **NEW: Token-based magic links** |
| Account Management | ❌ Not supported | ✅ Registration/reset | ✅ **NEW: User lifecycle** |
| Rate Limiting | ❌ Not supported | ✅ Built-in | ✅ **NEW: Rate limiter service** |
| Audit Logging | ❌ Not supported | ✅ Event hooks | ✅ **NEW: Event system** |
| Multi-tenancy | ❌ Not supported | ✅ Organizations | 🔄 Future enhancement |
| SAML/Enterprise SSO | ❌ Not supported | ❌ Not supported | 🔄 Future enhancement |

## Core Integration Principles

### 1. **Effect-First Design**
- All new features must use Effect types (`Effect<Success, Error>`)
- Service pattern with Context for dependency injection
- Request/Resolver pattern for batching and caching where beneficial
- Type-safe errors extending `Data.TaggedError`

### 2. **Storage-Agnostic Implementation**
- Maintain interface-based storage pattern
- Users implement storage adapters for their database
- No database dependencies or ORM coupling
- Support for both SQL and NoSQL backends

### 3. **Security-First Approach**
- Follow OWASP, Oslo, and Copenhagen Book guidelines
- Timing-safe comparisons for all sensitive operations
- Cryptographically secure random generation
- Input validation at service boundaries

### 4. **Composability Over Configuration**
- Prefer composable services over monolithic configuration objects
- Enable feature opt-in via layer composition
- Allow custom implementations via trait pattern

## Integrated Features

### 1. OAuth2/OIDC Provider Framework ✨ NEW

**Inspired by:** BetterAuth's provider architecture and social login support

**Implementation:**
- Generic OAuth2 client with authorization code flow
- Pre-built providers for major platforms (Google, GitHub, Discord, Microsoft)
- Extensible provider interface for custom OAuth2 services
- Token exchange and user info retrieval
- State parameter CSRF protection

**Storage Interfaces:**
```typescript
interface OAuthStateStore {
  create: (state: OAuthState) => Effect<OAuthState, AuthError>
  get: (state: string) => Effect<OAuthState, OAuthStateNotFoundError>
  delete: (state: string) => Effect<void, AuthError>
}

interface OAuthAccountStore {
  create: (account: OAuthAccount) => Effect<OAuthAccount, AuthError>
  get: (provider: string, providerId: string) => Effect<OAuthAccount, OAuthAccountNotFoundError>
  linkToUser: (userId: string, account: OAuthAccount) => Effect<void, AuthError>
  unlinkFromUser: (userId: string, provider: string) => Effect<void, AuthError>
}
```

**Services:**
- `OAuthService`: Core OAuth2 flow management
- `makeOAuthProvider`: Factory for provider configurations
- Provider implementations: Google, GitHub, Discord, Microsoft, Apple

**Usage:**
```typescript
const oauth = yield* Auth.makeOAuthService({
  providers: {
    google: {
      clientId: "...",
      clientSecret: "...",
      redirectUri: "https://example.com/auth/callback"
    }
  }
})

// Step 1: Generate authorization URL
const { url, state } = yield* oauth.generateAuthorizationUrl("google", {
  scopes: ["email", "profile"]
})

// Step 2: Handle callback and exchange code
const result = yield* oauth.handleCallback("google", {
  code: callbackCode,
  state: callbackState
})

// result contains: { providerId, email, name, picture, accessToken, refreshToken }
```

### 2. Email Verification Service ✨ NEW

**Inspired by:** BetterAuth's email verification flows and token management

**Implementation:**
- Token-based email verification (crypto-secure 32-byte tokens)
- Configurable expiration (default: 24 hours)
- Support for both signup and email change verification
- Rate limiting on verification attempts
- Email delivery abstraction (user provides email sender)

**Storage Interface:**
```typescript
interface EmailVerificationStore {
  create: (verification: EmailVerification) => Effect<EmailVerification, AuthError>
  get: (token: string) => Effect<EmailVerification, VerificationNotFoundError>
  delete: (token: string) => Effect<void, AuthError>
  deleteByUserId: (userId: string) => Effect<void, AuthError>
}
```

**Service:**
```typescript
interface EmailVerificationService {
  createVerification: (userId: string, email: string) => Effect<{ token: string, expiresAt: number }, AuthError>
  verifyToken: (token: string) => Effect<{ userId: string, email: string }, VerificationError>
  resendVerification: (userId: string) => Effect<void, AuthError | RateLimitError>
}
```

**Usage:**
```typescript
const emailVerifier = yield* Auth.makeEmailVerificationService({
  expiresIn: 24 * 60 * 60 * 1000, // 24 hours
  sendEmail: (to, token) => 
    Effect.tryPromise(() => 
      emailService.send({
        to,
        subject: "Verify your email",
        html: `Click here: https://example.com/verify?token=${token}`
      })
    )
})

// Create verification
const { token } = yield* emailVerifier.createVerification("user-123", "user@example.com")

// Verify token
const { userId, email } = yield* emailVerifier.verifyToken(userSubmittedToken)
```

### 3. Magic Link Authentication ✨ NEW

**Inspired by:** BetterAuth's passwordless authentication via magic links

**Implementation:**
- One-time use tokens with short expiration (15 minutes default)
- Email-based passwordless authentication
- Optional session creation on successful verification
- Token invalidation after single use

**Storage Interface:**
```typescript
interface MagicLinkStore {
  create: (link: MagicLink) => Effect<MagicLink, AuthError>
  get: (token: string) => Effect<MagicLink, MagicLinkNotFoundError>
  delete: (token: string) => Effect<void, AuthError>
}
```

**Service:**
```typescript
interface MagicLinkService {
  createMagicLink: (email: string) => Effect<{ token: string, expiresAt: number }, AuthError>
  verifyMagicLink: (token: string) => Effect<{ userId: string, email: string }, MagicLinkError>
}
```

**Usage:**
```typescript
const magicLink = yield* Auth.makeMagicLinkService({
  expiresIn: 15 * 60 * 1000, // 15 minutes
  sendEmail: (to, url) => 
    Effect.tryPromise(() => 
      emailService.send({
        to,
        subject: "Sign in to your account",
        html: `Click here to sign in: ${url}`
      })
    )
})

// Create magic link
const { token } = yield* magicLink.createMagicLink("user@example.com")

// Verify and sign in
const { userId } = yield* magicLink.verifyMagicLink(userClickedToken)
const session = yield* sessionManager.createSession(userId)
```

### 4. Rate Limiting Service ✨ NEW

**Inspired by:** BetterAuth's built-in rate limiting for security

**Implementation:**
- Token bucket algorithm for flexible rate limiting
- Support for different rate limits by operation type
- IP-based and user-based rate limiting
- Sliding window implementation
- Storage-backed for distributed systems

**Storage Interface:**
```typescript
interface RateLimitStore {
  get: (key: string) => Effect<RateLimitEntry | null, never>
  set: (key: string, entry: RateLimitEntry, ttl: number) => Effect<void, AuthError>
  increment: (key: string, ttl: number) => Effect<number, AuthError>
}
```

**Service:**
```typescript
interface RateLimiter {
  checkLimit: (key: string, config: RateLimitConfig) => Effect<boolean, RateLimitError>
  consumeToken: (key: string, config: RateLimitConfig) => Effect<void, RateLimitError>
  resetLimit: (key: string) => Effect<void, AuthError>
}

interface RateLimitConfig {
  maxRequests: number
  windowMs: number
  blockDurationMs?: number
}
```

**Usage:**
```typescript
const rateLimiter = yield* Auth.makeRateLimiter()

// Check rate limit before operation
yield* rateLimiter.consumeToken(`login:${ip}`, {
  maxRequests: 5,
  windowMs: 15 * 60 * 1000, // 15 minutes
  blockDurationMs: 30 * 60 * 1000 // 30 minutes block on exceed
})

// Rate limit configurations
const loginLimit: RateLimitConfig = { maxRequests: 5, windowMs: 15 * 60 * 1000 }
const passwordResetLimit: RateLimitConfig = { maxRequests: 3, windowMs: 60 * 60 * 1000 }
const emailVerificationLimit: RateLimitConfig = { maxRequests: 3, windowMs: 10 * 60 * 1000 }
```

### 5. Account Management Utilities ✨ NEW

**Inspired by:** BetterAuth's user lifecycle management

**Implementation:**
- User registration with validation
- Password reset flow with secure tokens
- Account deletion with cascade operations
- Email change with verification
- Profile update utilities

**Services:**
```typescript
interface AccountService {
  register: (email: string, password: string, attributes?: Record<string, unknown>) => Effect<User, AuthError>
  requestPasswordReset: (email: string) => Effect<void, AuthError>
  resetPassword: (token: string, newPassword: string) => Effect<void, PasswordResetError>
  changeEmail: (userId: string, newEmail: string) => Effect<void, AuthError>
  deleteAccount: (userId: string, password: string) => Effect<void, AuthError>
}
```

**Storage Interfaces:**
```typescript
interface PasswordResetStore {
  create: (reset: PasswordReset) => Effect<PasswordReset, AuthError>
  get: (token: string) => Effect<PasswordReset, PasswordResetNotFoundError>
  delete: (token: string) => Effect<void, AuthError>
}

interface UserManagementStore extends UserStore {
  create: (user: User) => Effect<User, AuthError>
  update: (user: User) => Effect<User, AuthError>
  delete: (userId: string) => Effect<void, AuthError>
  findByEmail: (email: string) => Effect<User | null, AuthError>
  setCredentials: (userId: string, hashedPassword: string) => Effect<void, AuthError>
}
```

**Usage:**
```typescript
const account = yield* Auth.makeAccountService()

// Registration
const user = yield* account.register("user@example.com", "securePassword123", {
  name: "John Doe"
})

// Password reset request
yield* account.requestPasswordReset("user@example.com")

// Reset password with token
yield* account.resetPassword(resetToken, "newSecurePassword456")

// Change email (triggers verification)
yield* account.changeEmail("user-123", "newemail@example.com")

// Delete account
yield* account.deleteAccount("user-123", "currentPassword")
```

### 6. Event System & Audit Logging ✨ NEW

**Inspired by:** BetterAuth's event hooks and extensibility

**Implementation:**
- Type-safe event emitter for authentication events
- Subscribable event streams
- Built-in events for all auth operations
- Custom event support
- Audit trail generation

**Event Types:**
```typescript
type AuthEvent =
  | { _tag: "UserRegistered"; userId: string; email: string; timestamp: number }
  | { _tag: "UserLoggedIn"; userId: string; sessionId: string; ip?: string; timestamp: number }
  | { _tag: "UserLoggedOut"; userId: string; sessionId: string; timestamp: number }
  | { _tag: "PasswordChanged"; userId: string; timestamp: number }
  | { _tag: "PasswordResetRequested"; userId: string; email: string; timestamp: number }
  | { _tag: "EmailVerified"; userId: string; email: string; timestamp: number }
  | { _tag: "TwoFactorEnabled"; userId: string; method: "totp" | "hotp"; timestamp: number }
  | { _tag: "OAuthLinked"; userId: string; provider: string; timestamp: number }
  | { _tag: "SuspiciousActivity"; userId: string; reason: string; timestamp: number }
```

**Service:**
```typescript
interface EventEmitter {
  emit: (event: AuthEvent) => Effect<void, never>
  subscribe: (eventType: string, handler: (event: AuthEvent) => Effect<void, never>) => Effect<void, never>
  getEvents: (userId: string, filters?: EventFilters) => Effect<readonly AuthEvent[], AuthError>
}
```

**Storage Interface:**
```typescript
interface EventStore {
  create: (event: AuthEvent) => Effect<void, AuthError>
  query: (userId: string, filters?: EventFilters) => Effect<readonly AuthEvent[], AuthError>
}
```

**Usage:**
```typescript
const events = yield* Auth.makeEventEmitter()

// Subscribe to events
yield* events.subscribe("UserLoggedIn", (event) =>
  Effect.sync(() => console.log(`User ${event.userId} logged in from ${event.ip}`))
)

// Emit events (done automatically by services)
yield* events.emit({
  _tag: "UserRegistered",
  userId: "user-123",
  email: "user@example.com",
  timestamp: Date.now()
})

// Query audit log
const userEvents = yield* events.getEvents("user-123", {
  eventTypes: ["UserLoggedIn", "UserLoggedOut"],
  since: Date.now() - 30 * 24 * 60 * 60 * 1000 // Last 30 days
})
```

## Architectural Differences & Incompatibilities

### Differences from BetterAuth

1. **Framework Philosophy**
   - **BetterAuth**: Configuration-first, opinionated defaults, batteries-included
   - **effect-auth**: Composition-first, minimal core, bring-your-own-storage

2. **Type System**
   - **BetterAuth**: Standard TypeScript, Promise-based
   - **effect-auth**: Effect-based, functional error handling, composable effects

3. **Storage Layer**
   - **BetterAuth**: ORM adapters (Prisma, Drizzle), automatic migrations
   - **effect-auth**: Interface-based, users implement stores, no database coupling

4. **Configuration**
   - **BetterAuth**: Single configuration object with extensive options
   - **effect-auth**: Service composition with Effect layers

5. **Plugin System**
   - **BetterAuth**: Plugin API with lifecycle hooks
   - **effect-auth**: Service trait pattern with context layers

### Incompatibilities

1. **No Direct Drop-in Replacement**
   - effect-auth cannot directly replace BetterAuth due to different type systems
   - Migration requires rewriting auth logic to use Effect types

2. **Storage Migration Required**
   - BetterAuth's database schemas are not compatible
   - Users must write migration scripts if moving from BetterAuth

3. **Different Session Format**
   - BetterAuth uses JWT or database sessions
   - effect-auth uses database sessions only (no JWT yet)

4. **Plugin Ecosystem**
   - BetterAuth has npm-installable plugins
   - effect-auth uses composable Effect services (no separate plugin packages)

### Why Not Wrap BetterAuth?

We considered wrapping BetterAuth but decided against it for:

1. **Type Safety Loss**: Converting between Promise and Effect types loses guarantees
2. **Impedance Mismatch**: BetterAuth's Promise-based model conflicts with Effect
3. **Dependency Weight**: Adding BetterAuth as dependency increases bundle size
4. **Feature Duplication**: Many features (sessions, passwords) already implemented
5. **Effect-First Design**: Native Effect implementation provides better DX for Effect users

## Implementation Strategy

### Phase 1: Core Infrastructure (Current PR)
- [x] Analysis and documentation
- [ ] OAuth2 provider framework
- [ ] Email verification service
- [ ] Magic link service
- [ ] Rate limiting service
- [ ] Account management utilities
- [ ] Event system

### Phase 2: Provider Implementations
- [ ] Google OAuth provider
- [ ] GitHub OAuth provider
- [ ] Discord OAuth provider
- [ ] Microsoft OAuth provider
- [ ] Generic OAuth2 provider

### Phase 3: Advanced Features
- [ ] Refresh token support
- [ ] Device tracking
- [ ] Session history
- [ ] Multi-factor backup codes
- [ ] Account recovery flows

### Phase 4: Developer Experience
- [ ] CLI tooling for common tasks
- [ ] Code generation for storage adapters
- [ ] Migration utilities
- [ ] Example integrations (Next.js, Remix, etc.)

## Migration from BetterAuth

If you're currently using BetterAuth and want to migrate to effect-auth:

### Step 1: Assess Compatibility
- Review your current BetterAuth configuration
- Identify which features you're using
- Check feature availability in effect-auth

### Step 2: Implement Storage Adapters
```typescript
// Map BetterAuth data models to effect-auth interfaces
const sessionStore: SessionStore = {
  create: (session) => Effect.tryPromise(() => db.session.create({ data: session })),
  // ... implement other methods
}
```

### Step 3: Migrate User Data
```typescript
// Migrate password hashes (if using same algorithm)
// Migrate session data
// Migrate OAuth connections
```

### Step 4: Update Authentication Logic
```typescript
// Before (BetterAuth)
const session = await auth.createSession({ userId: "123" })

// After (effect-auth)
const session = yield* sessionManager.createSession("123")
```

### Step 5: Test Thoroughly
- Test all authentication flows
- Verify session management
- Test OAuth connections
- Validate security measures

## Security Considerations

All BetterAuth-inspired features maintain effect-auth's security standards:

- ✅ **Timing-safe comparisons** for all token/password checks
- ✅ **CSRF protection** for OAuth state parameters
- ✅ **Rate limiting** on all sensitive endpoints
- ✅ **Secure random generation** for tokens (crypto.randomBytes)
- ✅ **Token expiration** for all temporary tokens
- ✅ **Input validation** at service boundaries
- ✅ **OWASP compliance** for all authentication flows

## Testing Strategy

### Unit Tests
- OAuth flow state management
- Email verification token generation/validation
- Magic link creation/verification
- Rate limiter token bucket algorithm
- Account management operations

### Integration Tests
- Full OAuth flow with mock providers
- Email verification end-to-end
- Password reset flow
- Rate limiting under load

### Security Tests
- Token brute-force resistance
- CSRF protection validation
- Rate limit bypass attempts
- Timing attack resistance

## Documentation Updates

Following documentation will be updated:
- [x] `docs/BETTERAUTH_INTEGRATION.md` (this document)
- [ ] `README.md` - Add OAuth and account management examples
- [ ] `ARCHITECTURE.md` - Document new services
- [ ] API reference for new features
- [ ] Migration guide from BetterAuth

## Examples

Example implementations will be added to `examples/`:
- [ ] `oauth-flow.ts` - Complete OAuth integration
- [ ] `email-verification.ts` - Email verification flow
- [ ] `magic-link-auth.ts` - Passwordless authentication
- [ ] `account-management.ts` - User lifecycle
- [ ] `rate-limiting.ts` - Rate limiter usage

## References

- [BetterAuth Documentation](https://www.better-auth.com/)
- [BetterAuth GitHub](https://github.com/better-auth/better-auth)
- [OAuth 2.0 RFC 6749](https://www.rfc-editor.org/rfc/rfc6749)
- [OpenID Connect Core 1.0](https://openid.net/specs/openid-connect-core-1_0.html)
- [OWASP Authentication Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html)
- [Copenhagen Book](https://lucia-auth.com/copenhagen)
- [Oslo Library](https://github.com/pilcrowonpaper/oslo)

## Conclusion

The integration of BetterAuth-inspired features into effect-auth expands its capabilities while maintaining its Effect-first philosophy and storage-agnostic design. This approach provides:

1. **Feature Parity**: Comparable features to BetterAuth for common auth needs
2. **Effect-Native**: Fully integrated with Effect's type system and patterns
3. **Flexibility**: Maintain storage-agnostic, composable architecture
4. **Security**: OWASP-compliant, secure-by-default implementations
5. **Extensibility**: Easy to add custom providers and flows

The integration focuses on learning from BetterAuth's excellent developer experience while adapting features to fit effect-auth's architectural principles.
