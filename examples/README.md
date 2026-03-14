# Examples

This directory contains complete, runnable examples demonstrating the features of effect-auth.

## Running the Examples

Make sure you have built the project first:

```bash
bun run build
```

Then you can run any example directly with Bun:

```bash
bun run examples/basic-auth.ts
```

## Available Examples

### 1. Basic Authentication (`basic-auth.ts`)

Demonstrates the complete authentication flow:

- Password hashing with PBKDF2-SHA256
- Session creation and management
- Session validation
- Credential verification
- Session invalidation

**Run:**
```bash
bun run examples/basic-auth.ts
```

### 2. Authorization (`authorization.ts`)

Demonstrates role-based access control:

- Setting up roles and permissions
- Checking permissions for different users
- Using `requirePermission` to protect operations
- Handling permission denied errors
- Multiple roles per user

**Run:**
```bash
bun run examples/authorization.ts
```

## Key Concepts Demonstrated

### Storage Adapters

Both examples show how to implement storage adapters:

- **SessionStore**: For persisting sessions (using in-memory Map for demo)
- **UserStore**: For retrieving user data
- **RoleStore**: For role-based authorization

In production, replace these with real database implementations (PostgreSQL, Redis, MongoDB, etc.).

### Effect Composition

The examples demonstrate Effect's powerful composition:

```typescript
const program = Effect.gen(function* () {
  const service = yield* MyService
  const result = yield* service.doSomething()
  return result
})
```

### Error Handling

Examples show Effect's type-safe error handling:

```typescript
const result = yield* Effect.either(operation)
if (result._tag === "Left") {
  // Handle error
} else {
  // Handle success
}
```

### Dependency Injection

All examples use Effect's Context for dependency injection:

```typescript
Effect.provide(
  program,
  Context.merge(
    Context.make(SessionStore, mySessionStore),
    Context.make(UserStore, myUserStore)
  )
)
```

## Creating Your Own Examples

To create a new example:

1. Create a new `.ts` file in this directory
2. Import from `../src/index.js`
3. Implement required storage adapters
4. Create an Effect program demonstrating the feature
5. Add error handling and logging
6. Export your program and run function

## Production Considerations

When adapting these examples for production:

1. **Use Real Databases**: Replace in-memory Maps with proper database connections
2. **Add Error Handling**: Implement comprehensive error handling and logging
3. **Secure Storage**: Use secure, encrypted storage for sensitive data
4. **Connection Pooling**: Use connection pools for database access
5. **Rate Limiting**: Implement rate limiting for authentication attempts
6. **Monitoring**: Add monitoring and alerting for security events
7. **Testing**: Write comprehensive tests for your implementations

## Further Reading

- [Effect Documentation](https://effect.website/)
- [Lucia Authentication](https://lucia-auth.com/)
- [The Copenhagen Book](https://lucia-auth.com/copenhagen)
- [Oslo Library](https://github.com/pilcrowonpaper/oslo)
