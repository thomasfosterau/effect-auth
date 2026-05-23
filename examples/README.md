# Examples

Each example is its own workspace package under this directory. Drop into a
package and run it directly, or invoke it from the repo root via Bun's
`--filter` flag.

## Running

Build the library first so its declaration files exist:

```bash
bun run build
```

Then run any example via its workspace name:

```bash
bun --filter @effect-auth-examples/basic-auth start
```

…or by entering the directory:

```bash
cd examples/basic-auth && bun run index.ts
```

## Available Examples

| Package                                   | Path                 | Demonstrates                                                                                      |
| ----------------------------------------- | -------------------- | ------------------------------------------------------------------------------------------------- |
| `@effect-auth-examples/basic-auth`        | `basic-auth/`        | Password hashing, session create/validate/invalidate.                                             |
| `@effect-auth-examples/authorization`     | `authorization/`     | Role-based access control, `requirePermission`.                                                   |
| `@effect-auth-examples/oauth`             | `oauth/`             | OAuth 2.0 social-login flows.                                                                     |
| `@effect-auth-examples/webauthn`          | `webauthn/`          | Passkey / WebAuthn flow.                                                                          |
| `@effect-auth-examples/multi-algorithm`   | `multi-algorithm/`   | Multi-algorithm password verification.                                                            |
| `@effect-auth-examples/northwind-traders` | `northwind-traders/` | End-to-end app: sign-up, email verification, sessions, RBAC, rate-limiting, OAuth URL generation. |

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
  const service = yield* MyService;
  const result = yield* service.doSomething();
  return result;
});
```

### Error Handling

Examples show Effect's type-safe error handling:

```typescript
const result = yield * Effect.either(operation);
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
  Context.merge(Context.make(SessionStore, mySessionStore), Context.make(UserStore, myUserStore)),
);
```

## Creating Your Own Examples

Each example is a standalone workspace package. To add one:

1. Create a new directory under `examples/` (e.g. `examples/my-feature/`).
2. Add a `package.json` with `"effect-auth": "workspace:*"` as a dependency and
   a `start` script that runs your entry file.
3. Add a `tsconfig.json` extending `../../tsconfig.base.json`.
4. Add a `project.json` if you want an nx target for typecheck (mirror the
   other examples).
5. Write your example as `index.ts` (or any other entry file referenced from
   your `start` script). Import `* as Auth from "effect-auth"`.
6. Run `bun install` at the repo root so the workspace is linked.

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
