# Effect Auth Architecture

## Overview

Effect Auth is a generic, type-safe authentication and authorization library for Effect, following best practices from Lucia, Copenhagen, and Oslo projects.

## Core Principles

1. **Generic & Flexible**: Use Effect's Request/Resolver pattern for maximum customization
2. **Type-Safe**: Full TypeScript support with comprehensive error types
3. **Composable**: Leverage Effect's composition capabilities
4. **Storage-Agnostic**: Bring your own database/storage backend
5. **Secure by Default**: Following industry best practices

## Architecture

### 1. Core Types (`src/types.ts`)

Defines fundamental data structures:
- `User`: User representation with ID and attributes
- `Session`: Active session with expiration
- `SessionWithUser`: Combined session and user data
- `SessionConfig`: Session management configuration
- `HashedPassword`: Hashed password with algorithm info
- `Permission`: Permission check result

### 2. Error Types (`src/errors.ts`)

Type-safe errors using Effect's Data.TaggedError:
- `AuthError`: Base authentication error
- `InvalidCredentialsError`: Invalid credentials
- `SessionNotFoundError`: Session not found
- `SessionExpiredError`: Session expired
- `UserNotFoundError`: User not found
- `PermissionDeniedError`: Permission denied
- `HashingError`: Password hashing error

### 3. Request Types (`src/requests.ts`)

Effect Request types for all operations:
- `CreateSessionRequest`: Create new session
- `ValidateSessionRequest`: Validate existing session
- `InvalidateSessionRequest`: Invalidate session
- `InvalidateUserSessionsRequest`: Invalidate all user sessions
- `VerifyCredentialsRequest`: Verify user credentials
- `HashPasswordRequest`: Hash a password
- `VerifyPasswordRequest`: Verify password against hash
- `CheckPermissionRequest`: Check user permissions

### 4. Password Hashing (`src/password.ts`)

Secure password hashing following Oslo guidelines:
- **Algorithm**: PBKDF2-SHA256
- **Iterations**: 210,000 (OWASP recommended)
- **Key Length**: 64 bytes
- **Salt Length**: 16 bytes (128 bits)
- **Timing-Safe Comparison**: Uses `crypto.timingSafeEqual`

**Service Interface:**
```typescript
interface PasswordHasher {
  hash: (password: string) => Effect<HashedPassword, HashingError>
  verify: (password: string, hash: string) => Effect<boolean, HashingError>
}
```

### 5. Session Management (`src/session.ts`)

Following Lucia/Copenhagen guidelines:

**Key Features:**
- Secure random session IDs (160 bits entropy)
- Active period timeout (e.g., 30 days max lifetime)
- Idle period timeout (e.g., 14 days of inactivity)
- Automatic session renewal
- Session validation with expiration checks

**Service Interfaces:**

```typescript
interface SessionStore {
  create: (session: Session) => Effect<Session, AuthError>
  get: (sessionId: string) => Effect<Session, SessionNotFoundError>
  update: (session: Session) => Effect<Session, AuthError>
  delete: (sessionId: string) => Effect<void, AuthError>
  deleteByUserId: (userId: string) => Effect<void, AuthError>
}

interface UserStore {
  get: (userId: string) => Effect<User, UserNotFoundError>
  getCredentials: (userId: string) => Effect<string, UserNotFoundError>
}

interface SessionManager {
  createSession: (userId: string, attributes?: Record<string, unknown>) => Effect<Session, AuthError>
  validateSession: (sessionId: string) => Effect<SessionWithUser, SessionNotFoundError | SessionExpiredError | UserNotFoundError>
  invalidateSession: (sessionId: string) => Effect<void, AuthError>
  invalidateUserSessions: (userId: string) => Effect<void, AuthError>
}
```

### 6. Resolvers (`src/resolvers.ts`)

Effect RequestResolvers for all Request types:
- Connects Requests to their implementations
- Uses Effect's `RequestResolver.fromEffect`
- Integrates with SessionManager, PasswordHasher, and stores

### 7. Authorization (`src/authorization.ts`)

Role-Based Access Control (RBAC):

**Service Interfaces:**

```typescript
interface AuthorizationPolicy {
  checkPermission: (userId: string, resource: string, action: string) => Effect<boolean, PermissionDeniedError>
}

interface RoleStore {
  getUserRoles: (userId: string) => Effect<readonly string[], never>
  getRolePermissions: (role: string) => Effect<readonly { resource: string; action: string }[], never>
}
```

**Utility Functions:**
- `makeRoleBasedPolicy()`: Create role-based authorization policy
- `requirePermission()`: Helper to enforce permissions (throws if denied)

### 8. OTP Utilities (`src/otp.ts`)

One-Time Password (OTP) support for Two-Factor Authentication:

**Supported Algorithms:**
- **TOTP (Time-Based OTP)**: RFC 6238 compliant
- **HOTP (HMAC-Based OTP)**: RFC 4226 compliant

**Key Features:**
- Cryptographically secure secret generation
- Base32 encoding/decoding for secrets
- Support for SHA-1, SHA-256, and SHA-512 algorithms
- Configurable code length (default: 6 digits)
- Configurable time periods for TOTP (default: 30 seconds)
- Time window support for TOTP verification (default: ±1 step)
- OTP URI generation for QR codes (otpauth:// protocol)
- Timing-safe token comparison

**Core Functions:**

```typescript
// Secret generation
generateSecret(length?: number): Effect<Buffer, HashingError>
generateBase32Secret(length?: number): Effect<string, HashingError>

// HOTP (counter-based)
generateHOTP(secret, counter, config?): Effect<string, HashingError>
verifyHOTP(token, secret, counter, config?): Effect<boolean, HashingError>

// TOTP (time-based)
generateTOTP(secret, config?): Effect<string, HashingError>
verifyTOTP(token, secret, config?): Effect<boolean, HashingError>

// URI generation for QR codes
generateOTPURI(params: OTPURIParams): string
```

**Security Properties:**
- Uses Node.js crypto module for HMAC and random generation
- Implements dynamic truncation per RFC 4226 Section 5.3
- Timing-safe comparison using `crypto.timingSafeEqual`
- Compatible with Google Authenticator and other standard authenticator apps

## Request/Resolver Pattern

The library uses Effect's Request/Resolver pattern for flexibility:

```typescript
// Define a request
const validateSession = Effect.request(
  ValidateSessionRequest({ sessionId: "abc123" }),
  makeValidateSessionResolver
)

// Execute the request
const result = await Effect.runPromise(
  Effect.provide(validateSession, dependencies)
)
```

This pattern allows:
- **Batching**: Multiple requests can be batched together
- **Caching**: Requests can be cached automatically
- **Testability**: Easy to mock resolvers in tests
- **Composability**: Requests compose naturally with Effect

## Security Considerations

### Password Security
- ✅ PBKDF2-SHA256 with 210,000 iterations (OWASP recommended)
- ✅ Random salt per password (16 bytes)
- ✅ Timing-safe comparison to prevent timing attacks
- ✅ Never store plaintext passwords

### Session Security
- ✅ Cryptographically secure random IDs (160 bits entropy)
- ✅ Both active and idle timeout periods
- ✅ Automatic session expiration
- ✅ Session renewal on activity
- ✅ Ability to invalidate all user sessions

### Authorization Security
- ✅ Explicit permission checks
- ✅ Type-safe permission errors
- ✅ Principle of least privilege support
- ✅ Role-based access control

## Usage Patterns

### 1. Basic Authentication Flow

```typescript
// Hash password
const hasher = yield* PasswordHasher
const hashed = yield* hasher.hash("password")

// Create session after successful auth
const manager = yield* makeSessionManager(config)
const session = yield* manager.createSession("user-id")

// Validate session on subsequent requests
const { session, user } = yield* manager.validateSession(session.id)
```

### 2. Permission Checking

```typescript
// Check permission
const policy = yield* makeRoleBasedPolicy()
const canCreate = yield* policy.checkPermission("user-id", "posts", "create")

// Require permission (throws if denied)
yield* requirePermission("user-id", "posts", "create")
```

### 3. Custom Storage Implementation

Users implement storage interfaces for their database:

```typescript
const sessionStore: SessionStore = {
  create: (session) => 
    // Your database implementation
    Effect.tryPromise(() => db.sessions.insert(session)),
  // ... other methods
}
```

## Testing

The library includes comprehensive tests:
- **Password hashing tests**: Verify security properties
- **Session management tests**: Test creation, validation, expiration
- **Mock implementations**: Easy-to-use mocks for testing

## Dependencies

- **effect**: Core Effect library (only runtime dependency)
- **typescript**: Development dependency
- **vitest**: Testing framework

## Future Enhancements

Possible future additions:
- ~~Two-factor authentication (TOTP, HOTP)~~ ✅ Implemented
- WebAuthn support
- OAuth 2.0 / OIDC integration
- Token-based authentication (JWT)
- Rate limiting utilities
- IP-based session validation
- User agent fingerprinting
- Session refresh tokens

## References

- [Lucia](https://lucia-auth.com/) - Authentication library and patterns
- [Copenhagen Book](https://lucia-auth.com/copenhagen) - Authentication best practices
- [Oslo](https://github.com/pilcrowonpaper/oslo) - Authentication primitives
- [Effect](https://effect.website/) - TypeScript effect system
- [OWASP Password Storage](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html)
- [RFC 6238](https://www.rfc-editor.org/rfc/rfc6238) - TOTP: Time-Based One-Time Password Algorithm
- [RFC 4226](https://www.rfc-editor.org/rfc/rfc4226) - HOTP: An HMAC-Based One-Time Password Algorithm
