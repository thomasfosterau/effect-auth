# Agent Guidelines for effect-auth

This document provides comprehensive guidelines for agents (AI assistants, developers, and contributors) working on the effect-auth repository. Following these guidelines ensures consistency, security, and adherence to best practices from Lucia, Copenhagen Book, and Oslo projects.

## Table of Contents

1. [Core Documentation References](#core-documentation-references)
2. [Security Requirements](#security-requirements)
3. [Code Patterns and Conventions](#code-patterns-and-conventions)
4. [Testing Requirements](#testing-requirements)
5. [Common Tasks and Procedures](#common-tasks-and-procedures)
6. [Security Checklist](#security-checklist)

---

## Core Documentation References

### Required Reading

Before making any changes to authentication or security-related code, familiarize yourself with:

1. **[The Copenhagen Book](https://lucia-auth.com/copenhagen)** - Authentication best practices guide
   - Session management patterns
   - Token generation and validation
   - Cookie security
   - CSRF protection

2. **[Lucia Documentation](https://lucia-auth.com/)** - Modern authentication library patterns
   - Session handling best practices
   - Database adapter patterns
   - User authentication flows

3. **[Oslo Library](https://github.com/pilcrowonpaper/oslo)** - Authentication primitives
   - Password hashing implementations
   - TOTP/HOTP utilities
   - WebAuthn utilities
   - Cryptographic utilities

4. **[Effect Documentation](https://effect.website/)** - Effect TypeScript framework
   - Effect types and composition
   - Request/Resolver pattern
   - Error handling with tagged errors
   - Service pattern with Context

5. **[OWASP Authentication Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html)**
   - Industry-standard authentication security practices

6. **[OWASP Password Storage Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html)**
   - Password hashing algorithms and parameters

---

## Security Requirements

### Critical Security Rules

**NEVER:**
- Store passwords in plaintext
- Use weak hashing algorithms (MD5, SHA1, bcrypt with low rounds)
- Perform string comparisons on security-sensitive values without timing-safe comparison
- Generate session IDs with insufficient entropy (minimum 160 bits)
- Log sensitive information (passwords, session tokens, API keys)
- Disable or reduce security measures for "convenience"
- Commit secrets or credentials to the repository

**ALWAYS:**
- Use timing-safe comparisons (`crypto.timingSafeEqual`) for all security-sensitive comparisons
- Use cryptographically secure random number generation (`crypto.randomBytes`)
- Validate and sanitize all inputs before processing
- Follow the principle of least privilege
- Document security-relevant decisions and trade-offs
- Run security checks before committing code

### Password Security Standards

Follow **Oslo** and **OWASP** guidelines:

1. **Hashing Algorithm**: PBKDF2-SHA256
   - **Iterations**: Minimum 210,000 (OWASP 2023 recommendation)
   - **Salt Length**: 16 bytes (128 bits) minimum
   - **Key Length**: 64 bytes
   - **Salt Generation**: Cryptographically secure random per password

2. **Format**: `algorithm$iterations$salt$hash`
   - Example: `pbkdf2-sha256$210000$hexsalt$hexhash`

3. **Verification**: Always use `crypto.timingSafeEqual` for hash comparison

4. **Implementation Reference**: `src/password.ts`

### Session Security Standards

Follow **Lucia** and **Copenhagen Book** guidelines:

1. **Session ID Generation**:
   - **Entropy**: Minimum 160 bits (20 bytes)
   - **Generation**: `crypto.randomBytes(20)`
   - **Encoding**: Base64url or hex encoding
   - **Format**: Cryptographically random string

2. **Session Expiration**:
   - **Active Period**: Maximum lifetime (e.g., 30 days)
   - **Idle Period**: Inactivity timeout (e.g., 14 days)
   - Both timeouts must be enforced

3. **Session Renewal**:
   - Update `lastActivityAt` on each validation
   - Extend session if within renewal threshold

4. **Session Invalidation**:
   - Provide ability to invalidate single sessions
   - Provide ability to invalidate all user sessions
   - Clean up expired sessions regularly

5. **Implementation Reference**: `src/session.ts`

### Cryptographic Standards

1. **Random Generation**: Always use `crypto.randomBytes` from Node.js `crypto` module
2. **Timing-Safe Comparison**: Use `crypto.timingSafeEqual` for all security-sensitive comparisons
3. **Key Derivation**: Use PBKDF2-SHA256 or better
4. **Never**: Implement custom cryptography

### Input Validation

1. **Validate Early**: Check inputs at the start of functions
2. **Type Checking**: Verify correct types before processing
3. **Length Checks**: Enforce minimum/maximum lengths
4. **Format Validation**: Validate expected formats
5. **Sanitization**: Sanitize inputs before use in security contexts

Example pattern from `src/password.ts`:

```typescript
if (!password || typeof password !== "string") {
  return yield* Effect.fail(new Errors.HashingError({
    message: "Password must be a non-empty string"
  }))
}

if (password.length < 1) {
  return yield* Effect.fail(new Errors.HashingError({
    message: "Password cannot be empty"
  }))
}
```

---

## Code Patterns and Conventions

### Effect Patterns

This codebase uses **Effect** for all operations. Follow these patterns:

1. **Effect.gen for Composition**:
```typescript
Effect.gen(function* () {
  const value1 = yield* someEffect
  const value2 = yield* anotherEffect(value1)
  return value2
})
```

2. **Error Handling with Tagged Errors**:
```typescript
import { Data } from "effect"

export class MyError extends Data.TaggedError("MyError")<{
  message: string
  cause?: unknown
}> {}
```

3. **Service Pattern with Context**:
```typescript
export interface MyService {
  readonly operation: (input: string) => Effect.Effect<Output, MyError>
}

export const MyService = Context.GenericTag<MyService>("@effect-auth/MyService")
```

4. **Return Effect Types**:
```typescript
// Good
const hash = (password: string): Effect.Effect<HashedPassword, HashingError> => { ... }

// Bad
const hash = async (password: string): Promise<HashedPassword> => { ... }
```

### TypeScript Conventions

1. **Type Exports**: Export types from their source files
2. **Named Exports**: Use named exports, not default exports
3. **Interface Naming**: Use descriptive names (e.g., `SessionStore`, not `ISessionStore`)
4. **Error Naming**: End error class names with `Error`
5. **Strict Mode**: All code must pass TypeScript strict mode checks

### File Organization

- `src/types.ts` - Core type definitions
- `src/errors.ts` - Tagged error definitions
- `src/requests.ts` - Request type definitions
- `src/resolvers.ts` - RequestResolver implementations
- `src/session.ts` - Session management
- `src/password.ts` - Password hashing
- `src/authorization.ts` - Authorization/permissions
- `src/index.ts` - Public API exports

### Naming Conventions

- **Functions**: camelCase (e.g., `createSession`, `validateSession`)
- **Types/Interfaces**: PascalCase (e.g., `Session`, `SessionManager`)
- **Constants**: UPPER_SNAKE_CASE (e.g., `ITERATIONS`, `SALT_LENGTH`)
- **Services**: PascalCase matching interface name
- **Test Files**: `*.test.ts` alongside source files

---

## Testing Requirements

### Test Framework

- **Framework**: Vitest with `@effect/vitest`
- **Build Command**: `npm run build`
- **Test Command**: `npm test`
- **Watch Mode**: `npm run test:watch`

### Test Coverage Requirements

1. **Password Hashing**:
   - Test hash generation
   - Test verification with valid password
   - Test verification with invalid password
   - Test input validation errors
   - Test timing-safe comparison

2. **Session Management**:
   - Test session creation
   - Test session validation
   - Test session expiration (idle timeout)
   - Test session expiration (active timeout)
   - Test session renewal
   - Test session invalidation

3. **Authorization**:
   - Test permission checking
   - Test role-based access control
   - Test permission denial

4. **Error Handling**:
   - Test all error cases
   - Test error messages
   - Test error types

### Test Patterns

Use Effect test utilities from `@effect/vitest`:

```typescript
import { describe, it, expect } from "vitest"
import { Effect } from "effect"
import { expect as effectExpect } from "@effect/vitest"

describe("MyFeature", () => {
  it("should work correctly", () =>
    Effect.gen(function* () {
      const result = yield* myOperation()
      expect(result).toBe(expected)
    }).pipe(Effect.runPromise))
})
```

### Security Testing

1. **Timing-Safe Comparison**: Verify timing-safe comparisons are used
2. **Random Generation**: Verify cryptographically secure random is used
3. **Input Validation**: Test all validation paths
4. **Error Leakage**: Ensure errors don't leak sensitive information

---

## Common Tasks and Procedures

### Adding a New Feature

1. **Research**: Check Lucia, Copenhagen Book, and Oslo documentation
2. **Design**: Design with Effect patterns (services, requests, errors)
3. **Types**: Define types in appropriate files
4. **Errors**: Define tagged errors in `src/errors.ts`
5. **Implementation**: Implement with Effect.gen
6. **Tests**: Write comprehensive tests
7. **Documentation**: Update README.md and ARCHITECTURE.md
8. **Security Review**: Verify security requirements are met

### Modifying Authentication Logic

1. **Understand**: Read Copenhagen Book section on the topic
2. **Review**: Review current implementation
3. **Security**: Identify security implications
4. **Test First**: Write failing tests for the change
5. **Implement**: Make minimal changes
6. **Verify**: Run tests and security checks
7. **Document**: Update documentation if behavior changes

### Adding New Password Hashing Algorithms

See `docs/MULTI_ALGORITHM.md` for detailed guidance on:
- Implementing new password hashers
- Creating multi-algorithm verifiers
- Migration strategies
- Security considerations

### Running Security Checks

Before committing code:

1. **Build**: `npm run build` - Must pass without errors
2. **Tests**: `npm test` - All tests must pass
3. **Manual Review**: Review changes for security issues
4. **Dependency Audit**: Run `npm audit` and address issues
5. **Secret Scanning**: Verify no secrets in code

### Making a Pull Request

1. **Branch**: Create a descriptive branch name
2. **Commits**: Make focused, atomic commits
3. **Tests**: Ensure all tests pass
4. **Documentation**: Update relevant documentation
5. **Description**: Write clear PR description explaining changes
6. **Security**: Note any security implications
7. **Review**: Request review from maintainers

---

## Security Checklist

Use this checklist when making changes to security-sensitive code:

### Password Hashing Changes

- [ ] Uses PBKDF2-SHA256 or stronger algorithm
- [ ] Uses >= 210,000 iterations
- [ ] Generates cryptographically secure random salt (16+ bytes)
- [ ] Uses `crypto.timingSafeEqual` for verification
- [ ] Validates all inputs before processing
- [ ] Returns appropriate tagged errors
- [ ] Does not log passwords or hashes
- [ ] Tests cover all security properties

### Session Management Changes

- [ ] Generates session IDs with >= 160 bits entropy
- [ ] Uses `crypto.randomBytes` for ID generation
- [ ] Enforces both active and idle timeouts
- [ ] Implements session renewal correctly
- [ ] Validates session expiration
- [ ] Does not log session tokens
- [ ] Provides session invalidation
- [ ] Tests cover all security scenarios

### Cryptographic Changes

- [ ] Uses Node.js `crypto` module
- [ ] No custom cryptography implemented
- [ ] Uses `crypto.timingSafeEqual` for sensitive comparisons
- [ ] Uses `crypto.randomBytes` for random generation
- [ ] Documents cryptographic decisions
- [ ] Tests verify cryptographic properties

### Input Validation Changes

- [ ] Validates types before processing
- [ ] Checks for null/undefined
- [ ] Validates string lengths
- [ ] Validates format (if applicable)
- [ ] Sanitizes inputs in security contexts
- [ ] Returns clear error messages
- [ ] Tests cover validation edge cases

### General Security

- [ ] No secrets or credentials in code
- [ ] No sensitive information in logs
- [ ] Follows principle of least privilege
- [ ] Error messages don't leak sensitive information
- [ ] All external inputs are validated
- [ ] All security-sensitive operations have tests
- [ ] Documentation reflects security considerations

---

## Additional Resources

### Official Documentation

- [Effect Website](https://effect.website/)
- [Lucia Auth](https://lucia-auth.com/)
- [The Copenhagen Book](https://lucia-auth.com/copenhagen)
- [Oslo on GitHub](https://github.com/pilcrowonpaper/oslo)

### Security Standards

- [OWASP Top 10](https://owasp.org/www-project-top-ten/)
- [OWASP Authentication Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html)
- [OWASP Password Storage Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html)
- [OWASP Session Management Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html)

### Code Examples

- See `examples/` directory for complete working examples
- See test files (`*.test.ts`) for usage patterns
- See `ARCHITECTURE.md` for architectural patterns

---

## Questions or Issues?

If you're unsure about:
- **Security implications**: Err on the side of caution, ask for review
- **Authentication patterns**: Check Copenhagen Book and Lucia docs
- **Effect patterns**: Check Effect documentation and existing code
- **Testing approach**: Look at existing tests for similar functionality

When in doubt, open an issue or ask for guidance from maintainers.

---

## Version History

- **1.0.0** (2026-02-07): Initial agent guidelines document

