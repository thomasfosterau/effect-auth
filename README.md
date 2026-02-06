# effect-auth

A generic authentication and authorization library for [Effect](https://effect.website/), following best practices from [Lucia](https://lucia-auth.com/), [Copenhagen](https://lucia-auth.com/copenhagen), and [Oslo](https://github.com/pilcrowonpaper/oslo) projects.

## Features

- 🔐 **Generic and Flexible**: Built with Effect's Request/Resolver pattern for maximum customization
- 🔒 **Secure by Default**: Following industry best practices for password hashing and session management
- 🎯 **Type-Safe**: Full TypeScript support with comprehensive type inference
- 🧩 **Composable**: Use Effect's powerful composition capabilities
- 🔄 **Bring Your Own Storage**: Implement storage adapters for any database or backend
- 📦 **Zero Lock-in**: No vendor lock-in, works with any storage backend

## Installation

```bash
npm install effect-auth effect
```

## Core Concepts

This library follows the Copenhagen Book guidelines for authentication:

- **Sessions**: Secure session management with automatic expiration and renewal
- **Password Hashing**: PBKDF2-SHA256 with recommended iterations (210,000+)
- **Request/Resolver Pattern**: Use Effect's Request/Resolver pattern for custom implementations
- **Authorization**: Flexible permission checking and role-based access control

## Quick Start

### 1. Implement Storage Adapters

First, implement the storage interfaces for your database:

```typescript
import { Effect } from "effect"
import * as Auth from "effect-auth"

// Implement session storage (e.g., Redis, PostgreSQL, etc.)
const sessionStore: Auth.SessionStore = {
  create: (session) => 
    Effect.succeed(session), // Your implementation
  get: (sessionId) => 
    Effect.fail(new Auth.SessionNotFoundError({ message: "Not found", sessionId })),
  update: (session) => 
    Effect.succeed(session),
  delete: (sessionId) => 
    Effect.void,
  deleteByUserId: (userId) => 
    Effect.void,
}

// Implement user storage
const userStore: Auth.UserStore = {
  get: (userId) => 
    Effect.fail(new Auth.UserNotFoundError({ message: "Not found", userId })),
  getCredentials: (userId) => 
    Effect.succeed("hashed-password"),
}
```

### 2. Create Session Manager

```typescript
import { Effect, Context } from "effect"
import * as Auth from "effect-auth"

const sessionConfig: Auth.SessionConfig = {
  sessionExpiresIn: {
    activePeriod: 1000 * 60 * 60 * 24 * 30, // 30 days
    idlePeriod: 1000 * 60 * 60 * 24 * 14,   // 14 days
  }
}

const program = Effect.gen(function* () {
  // Create session manager
  const manager = yield* Auth.makeSessionManager(sessionConfig)
  
  // Create a session
  const session = yield* manager.createSession("user-123", {
    ip: "127.0.0.1"
  })
  
  // Validate session
  const { session: validSession, user } = yield* manager.validateSession(session.id)
  
  return { session: validSession, user }
})

// Provide dependencies and run
const result = await Effect.runPromise(
  Effect.provide(
    program,
    Context.merge(
      Context.make(Auth.SessionStore, sessionStore),
      Context.make(Auth.UserStore, userStore)
    )
  )
)
```

### 3. Use Password Hashing

```typescript
import { Effect } from "effect"
import * as Auth from "effect-auth"

const program = Effect.gen(function* () {
  const hasher = yield* Auth.PasswordHasher
  
  // Hash a password
  const hashed = yield* hasher.hash("mySecurePassword")
  
  // Verify a password
  const isValid = yield* hasher.verify("mySecurePassword", hashed.hash)
  
  return isValid
})

// Run with the default hasher
const isValid = await Effect.runPromise(
  Effect.provide(program, Auth.PasswordHasherLive)
)
```

### 4. Use Request/Resolver Pattern

For more advanced use cases, use the Request/Resolver pattern:

```typescript
import { Effect } from "effect"
import * as Auth from "effect-auth"

// Create a session using a request
const createSession = Effect.request(
  Auth.CreateSessionRequest({ userId: "user-123" }),
  Auth.makeCreateSessionResolver
)

// Validate a session using a request
const validateSession = (sessionId: string) =>
  Effect.request(
    Auth.ValidateSessionRequest({ sessionId }),
    Auth.makeValidateSessionResolver
  )

// Compose multiple requests
const program = Effect.gen(function* () {
  const session = yield* createSession
  const { user } = yield* validateSession(session.id)
  return user
})
```

## Authorization

Implement role-based access control:

```typescript
import { Effect, Context } from "effect"
import * as Auth from "effect-auth"

// Implement your role store
const roleStore: Auth.RoleStore = {
  getUserRoles: (userId) => 
    Effect.succeed(["admin", "user"]),
  getRolePermissions: (role) => 
    Effect.succeed([
      { resource: "posts", action: "create" },
      { resource: "posts", action: "read" },
    ])
}

const program = Effect.gen(function* () {
  const policy = yield* Auth.makeRoleBasedPolicy()
  
  // Check permission
  const canCreate = yield* policy.checkPermission(
    "user-123",
    "posts",
    "create"
  )
  
  // Or require permission (throws if denied)
  yield* Auth.requirePermission("user-123", "posts", "create")
})

const result = await Effect.runPromise(
  Effect.provide(
    program,
    Context.make(Auth.RoleStore, roleStore)
  )
)
```

## WebAuthn / Passkeys

Implement passwordless authentication using WebAuthn (Passkeys):

```typescript
import { Effect, Context } from "effect"
import * as Auth from "effect-auth"

// Implement challenge store (temporary storage for challenges)
const challengeStore: Auth.ChallengeStore = {
  create: (challenge) => 
    Effect.succeed(challenge), // Store in Redis/memory
  get: (challenge) => 
    Effect.fail(new Auth.ChallengeNotFoundError({ message: "Not found" })),
  delete: (challenge) => 
    Effect.void
}

// Implement credential store (persistent storage for passkeys)
const credentialStore: Auth.CredentialStore = {
  create: (credential) => 
    Effect.succeed(credential), // Store in database
  get: (credentialId) => 
    Effect.fail(new Auth.CredentialNotFoundError({ 
      message: "Not found", 
      credentialId 
    })),
  update: (credential) => 
    Effect.succeed(credential),
  delete: (credentialId) => 
    Effect.void,
  getByUserId: (userId) => 
    Effect.succeed([]) // Return all user's credentials
}

const webAuthnConfig: Auth.WebAuthnConfig = {
  relyingPartyId: "example.com",
  relyingPartyName: "Example Corp",
  expectedOrigin: "https://example.com",
  challengeExpiresIn: 5 * 60 * 1000 // 5 minutes
}

// Registration flow
const registerPasskey = Effect.gen(function* () {
  const service = yield* Auth.makeWebAuthnService(webAuthnConfig)
  
  // Step 1: Generate challenge
  const { challenge } = yield* service.generateRegistrationChallenge({
    id: "user-123",
    name: "user@example.com",
    displayName: "User Name"
  })
  
  // Send challenge to client, client creates credential
  // Client returns: credentialId, attestationObject, clientDataJSON
  
  // Step 2: Verify registration response
  const result = yield* service.verifyRegistration(
    challenge,
    {
      credentialId: clientCredentialId,
      attestationObject: clientAttestationObject,
      clientDataJSON: clientDataJSON
    },
    "https://example.com"
  )
  
  // Credential is now stored and ready for authentication
  return result.credential
})

// Authentication flow
const authenticateWithPasskey = Effect.gen(function* () {
  const service = yield* Auth.makeWebAuthnService(webAuthnConfig)
  
  // Step 1: Generate challenge
  const { challenge } = yield* service.generateAuthenticationChallenge("user-123")
  
  // Send challenge to client, client signs with passkey
  // Client returns: credentialId, authenticatorData, clientDataJSON, signature
  
  // Step 2: Verify authentication response
  const result = yield* service.verifyAuthentication(
    challenge,
    {
      credentialId: clientCredentialId,
      authenticatorData: clientAuthenticatorData,
      clientDataJSON: clientDataJSON,
      signature: clientSignature
    },
    "https://example.com"
  )
  
  // User is authenticated, create session
  const sessionManager = yield* Auth.makeSessionManager(sessionConfig)
  const session = yield* sessionManager.createSession(result.credential.userId)
  
  return session
})

// Provide dependencies
const webAuthnDependencies = Context.merge(
  Context.make(Auth.ChallengeStore, challengeStore),
  Context.make(Auth.CredentialStore, credentialStore)
)

await Effect.runPromise(
  Effect.provide(registerPasskey, webAuthnDependencies)
)
```

## API Reference

### Types

- `User`: Represents a user with ID and attributes
- `Session`: Represents an active session
- `SessionWithUser`: Session combined with user data
- `SessionConfig`: Configuration for session expiration
- `HashedPassword`: Hashed password with algorithm info
- `Permission`: Permission check result
- `WebAuthnChallenge`: Temporary challenge for WebAuthn operations
- `WebAuthnCredential`: Stored passkey credential
- `WebAuthnConfig`: Configuration for WebAuthn service
- `WebAuthnUser`: User information for passkey registration

### Services

- `SessionStore`: Interface for session persistence
- `UserStore`: Interface for user data retrieval
- `SessionManager`: Service for managing sessions
- `PasswordHasher`: Service for password hashing and verification
- `AuthorizationPolicy`: Interface for permission checking
- `RoleStore`: Interface for role-based authorization
- `ChallengeStore`: Interface for WebAuthn challenge storage
- `CredentialStore`: Interface for WebAuthn credential storage
- `WebAuthnService`: Service for passkey registration and authentication

### Requests

All requests follow the Effect Request/Resolver pattern:

- `CreateSessionRequest`: Create a new session
- `ValidateSessionRequest`: Validate and retrieve a session
- `InvalidateSessionRequest`: Invalidate a session
- `InvalidateUserSessionsRequest`: Invalidate all user sessions
- `VerifyCredentialsRequest`: Verify user credentials
- `HashPasswordRequest`: Hash a password
- `VerifyPasswordRequest`: Verify a password against a hash
- `CheckPermissionRequest`: Check user permissions

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

1. Use PBKDF2-SHA256 with 210,000+ iterations
2. Generate random salts per password
3. Use timing-safe comparisons
4. Never store plaintext passwords

### Authorization

1. Implement principle of least privilege
2. Check permissions at the application layer
3. Use explicit permission checks
4. Log authorization failures

### WebAuthn

Following FIDO2/WebAuthn standards and Oslo guidelines:

1. Use secure random challenges (256 bits entropy)
2. Implement challenge expiration (5 minutes recommended)
3. Verify origin and relying party ID on every request
4. Use counter-based replay protection
5. Support multiple credentials per user
6. Store credentials securely with public keys only
7. Use ES256 (ECDSA with P-256) algorithm for broad compatibility

## Examples

See the `examples/` directory for complete examples:

- Basic session management
- User authentication flow
- Role-based access control
- Custom storage adapters
- WebAuthn passkey authentication

## Contributing

Contributions are welcome! Please open an issue or pull request to get started.

## License

ISC

## Acknowledgments

This library is inspired by and follows guidelines from:

- [Lucia](https://lucia-auth.com/) - Modern authentication library
- [The Copenhagen Book](https://lucia-auth.com/copenhagen) - Authentication best practices
- [Oslo](https://github.com/pilcrowonpaper/oslo) - Authentication primitives
- [Effect](https://effect.website/) - Powerful TypeScript framework

