# Contributing to effect-auth

Thank you for your interest in contributing to effect-auth! This document provides guidelines for contributing to this project.

## Table of Contents

- [Code of Conduct](#code-of-conduct)
- [Getting Started](#getting-started)
- [Development Setup](#development-setup)
- [Making Changes](#making-changes)
- [Testing](#testing)
- [Submitting Changes](#submitting-changes)
- [Security](#security)
- [Resources](#resources)

## Code of Conduct

Be respectful, inclusive, and considerate in all interactions. This project follows standard open source community guidelines.

## Getting Started

Before contributing, please:

1. **Read the documentation**:
   - [README.md](./README.md) - Project overview and usage
   - [ARCHITECTURE.md](./ARCHITECTURE.md) - Architectural design
   - [DESIGN.md](./DESIGN.md) - Settled API conventions and decision record
   - [AGENTS.md](./AGENTS.md) - Tooling and Effect-pattern guidelines
   - [SECURITY.md](./SECURITY.md) - Security requirements

2. **Understand the project**:
   - effect-auth is a generic authentication library for Effect
   - It follows best practices from [Lucia](https://lucia-auth.com/), [Copenhagen Book](https://lucia-auth.com/copenhagen), and [Oslo](https://github.com/pilcrowonpaper/oslo)
   - Security is the top priority

3. **Check existing issues**:
   - Look for [open issues](https://github.com/thomasfosterau/effect-auth/issues)
   - See if your contribution is already planned or in progress

## Development Setup

### Prerequisites

- **Node.js**: Version 22.18+ recommended
- **pnpm**: Version 11+ recommended
- **TypeScript**: Included as dev dependency

### Installation

1. **Fork the repository** on GitHub

2. **Clone your fork**:

   ```bash
   git clone https://github.com/YOUR_USERNAME/effect-auth.git
   cd effect-auth
   ```

3. **Install dependencies**:

   ```bash
   pnpm install
   ```

4. **Verify setup**:
   ```bash
   pnpm run build  # Should compile successfully
   pnpm run test   # Should pass all tests
   ```

### Project Structure

The core library (`@thomasfosterau/effect-auth`) lives at
`packages/effect-auth`; the repository root is a plain pnpm workspace.
Related feature modules are grouped into lowercase cluster directories (each
with its own `index.ts` barrel and matching `<pkg>/<cluster>` subpath
export); everything not listed in a cluster stays flat in `src/`. See
[ARCHITECTURE.md](./ARCHITECTURE.md) for the module map and
[DESIGN.md](./DESIGN.md) §D9 for the rationale behind the barrel and subpath
boundaries.

```
effect-auth/                       # pnpm workspaces monorepo (Vite+ toolchain)
├── packages/
│   ├── effect-auth/               # Core library (@thomasfosterau/effect-auth)
│   │   └── src/
│   │       ├── Types.ts           # Core domain types (schema'd User, Session, ...)
│   │       ├── Errors.ts          # Shared tagged error definitions
│   │       ├── Hooks.ts           # Hooks/plugin system
│   │       ├── PlatformCrypto.ts  # Default Crypto.Crypto layer (Web Crypto API)
│   │       ├── <Feature>.ts       # One module per flat, non-clustered feature
│   │       │                       # (AuthLifecycle, Jwt, Organization, Admin, ...)
│   │       │                       # incl. session: SessionService, SessionStore,
│   │       │                       # UserStore, TrustedDevice, ...
│   │       │                       # incl. authorization: Policy, Entity, Condition,
│   │       │                       # Authorizer, PolicyStore, Protected, Rbac, ...
│   │       ├── email/             # EmailAddress, EmailOtp, EmailPassword, EmailVerification
│   │       ├── password/          # Password, PasswordReset, HaveIBeenPwned
│   │       ├── oauth/             # OAuth, Scope
│   │       ├── multifactor/       # MultiFactor, Otp, OtpSecondFactor, WebAuthn
│   │       ├── http/              # HttpApi, HttpApiSchema, HttpServer, HttpClient, HttpMiddleware
│   │       ├── plugins/           # First-party Hooks plugins (AccountLockout, Audit, Captcha, ...)
│   │       ├── index.ts           # Public API barrel (curated root + cluster namespace re-exports)
│   │       └── *.test.ts          # Tests alongside source
│   ├── client/                    # @thomasfosterau/effect-auth-client (browser client + session store)
│   ├── react/                     # @thomasfosterau/effect-auth-react (React hooks)
│   ├── svelte/                    # @thomasfosterau/effect-auth-svelte (Svelte stores)
│   ├── vue/                       # @thomasfosterau/effect-auth-vue (Vue composables)
│   ├── solid/                     # @thomasfosterau/effect-auth-solid (Solid primitives)
│   ├── sql/                       # @thomasfosterau/effect-auth-sql (SqlClient store layers)
│   ├── alchemy/                   # @thomasfosterau/effect-auth-alchemy (Alchemy v2 + Cloudflare D1)
│   └── argon2/                    # @thomasfosterau/effect-auth-argon2 (Argon2id PasswordHasher)
├── docs/                          # ARCHITECTURE.md, DESIGN.md, SECURITY.md, CONTRIBUTING.md (this file), adr/, ...
├── README.md                      # Project overview
└── package.json                   # Private workspace root
```

## Making Changes

### Before You Start

1. **Create an issue** if one doesn't exist
2. **Discuss the approach** with maintainers
3. **Review [DESIGN.md](./DESIGN.md) and [AGENTS.md](./AGENTS.md)** for:
   - The settled API conventions (naming, layers, stores, errors)
   - Security requirements
   - Effect patterns and tooling

### Development Workflow

1. **Create a branch**:

   ```bash
   git checkout -b feature/your-feature-name
   ```

2. **Make your changes**:
   - Follow existing code style and the conventions in DESIGN.md
   - Use Effect patterns (see AGENTS.md — consult `effect-solutions`)
   - Add tests for new functionality
   - Update documentation as needed

3. **Write good commit messages**:

   ```
   Brief description (50 chars or less)

   More detailed explanation if needed. Explain what and why,
   not how. Reference issues with #123.
   ```

4. **Test your changes**:
   ```bash
   pnpm run build  # Ensure it compiles
   pnpm run test   # Ensure tests pass
   ```

### Code Style

- **TypeScript**: Use strict mode
- **Effect**: Use Effect.gen for composition
- **Naming**: Follow the conventions settled in DESIGN.md
- **Comments**: Add comments for complex logic or security decisions
- **Formatting**: Follow existing code style (`vp check --fix`)

### Security Requirements

**This is critical** - All security-related changes must:

1. **Follow OWASP guidelines**
2. **Use timing-safe comparisons** (`crypto.timingSafeEqual`)
3. **Use cryptographically secure random** (`crypto.randomBytes`)
4. **Validate all inputs**
5. **Never log sensitive data**

See [SECURITY.md](./SECURITY.md) for detailed security requirements.

### Adding New Features

Follow the module conventions in DESIGN.md (service class + `static layer`,
store interfaces with nullable lookups, tagged errors):

1. **Define shared types** in `src/Types.ts` (module-specific types live in the module)
2. **Define errors** in `src/Errors.ts` if shared, or module-local if only that module raises them
3. **Implement the module** in `src/<Feature>.ts`, or `src/<cluster>/<Feature>.ts` if it belongs to an existing cluster (`email/`, `http/`, `oauth/`, `password/`, `plugins/`, `multifactor/`)
4. **Add tests** in the sibling `<Feature>.test.ts` file
5. **Export from** the module's `index.ts` — the cluster barrel if clustered, otherwise `src/index.ts` (with a one-line doc comment)
6. **Document** in README.md and the site guides

Example: Adding a new password algorithm

1. Read the multi-algorithm guide (`site/src/content/docs/guides/multi-algorithm.md`)
2. Implement the hasher in `src/password/Password.ts` (or a dedicated package for native deps)
3. Add tests in `Password.test.ts`
4. Document in README.md and the guide

## Testing

### Running Tests

```bash
# Run all tests
pnpm run test

# Run tests in watch mode
pnpm run test:watch
```

### Writing Tests

- **Framework**: Vitest with @effect/vitest
- **Location**: Place tests next to source files (e.g., `password.test.ts` next to `password.ts`)
- **Coverage**: Test happy paths, error cases, edge cases, and security properties

Example test structure:

```typescript
import { describe, it, expect } from "vitest";
import { Effect } from "effect";

describe("MyFeature", () => {
  it("should work correctly", () =>
    Effect.gen(function* () {
      const result = yield* myFunction();
      expect(result).toBe(expected);
    }).pipe(Effect.runPromise));

  it("should handle errors", () =>
    Effect.gen(function* () {
      const result = yield* Effect.flip(myFunction());
      expect(result._tag).toBe("MyError");
    }).pipe(Effect.runPromise));
});
```

### Test Requirements

All changes should include:

1. **Unit tests** for new functionality
2. **Error case tests** for error handling
3. **Security tests** for security-sensitive code
4. **Edge case tests** for boundary conditions

## Submitting Changes

### Pull Request Process

1. **Create a changeset** (for features, fixes, or breaking changes):

   ```bash
   pnpm run changeset
   ```

   This will prompt you to:
   - Choose the version bump type (patch, minor, or major)
   - Write a summary of the changes

   A changeset file will be created in `.changeset/` - commit this with your changes.

2. **Update documentation**:
   - Update README.md if adding/changing features
   - Update ARCHITECTURE.md if changing design
   - Update examples if relevant

3. **Ensure quality**:

   ```bash
   pnpm run build  # Must compile successfully
   pnpm run test   # All tests must pass
   pnpm audit      # Check for vulnerabilities
   ```

4. **Push to your fork**:

   ```bash
   git push origin feature/your-feature-name
   ```

5. **Open a Pull Request**:
   - Use a clear, descriptive title
   - Explain what changes you made and why
   - Reference any related issues
   - Note any breaking changes
   - Note any security implications

### Pull Request Template

```markdown
## Description

Brief description of changes

## Motivation

Why are these changes needed?

## Changes Made

- Change 1
- Change 2

## Testing

How were these changes tested?

## Security Considerations

Any security implications?

## Breaking Changes

Are there any breaking changes?

## Related Issues

Fixes #123
```

### Review Process

1. **Automated checks** run on all PRs (tests, builds)
2. **Maintainer review** for code quality and design
3. **Security review** for security-sensitive changes
4. **Feedback addressed** by contributor
5. **Merge** when approved

### Release Process

Releases are automated using [Changesets](https://github.com/changesets/changesets):

1. **Changesets are merged**: When PRs with changesets are merged to `main`
2. **Release PR is created**: The Release workflow automatically creates a "Version Packages" PR
3. **Release PR is merged**: When the maintainer merges this PR:
   - Package versions are bumped based on changesets
   - CHANGELOG.md is updated
   - Changes are published to npm
   - Git tags are created

Contributors don't need to worry about versioning - just create changesets for your changes!

## Security

### Reporting Vulnerabilities

**DO NOT** open public issues for security vulnerabilities.

See [SECURITY.md](./SECURITY.md) for:

- How to report security issues
- Security requirements
- Security best practices

### Security Reviews

All changes to security-sensitive code require:

1. **Security review** against SECURITY.md
2. **Maintainer review**
3. **Test coverage** for security properties
4. **Documentation** of security decisions

Security-sensitive areas:

- Password hashing (`src/password/Password.ts`)
- Session management (`src/SessionService.ts`, `src/SessionCookieCache.ts`)
- Cookie flags, CSRF/trusted-origin checks (`src/http/HttpServer.ts`)
- Cryptographic operations (token generation, timing-safe comparison)
- Input validation
- Error handling (avoid information leakage / user enumeration)

## Resources

### Documentation

- [Effect Documentation](https://effect.website/)
- [The Copenhagen Book](https://lucia-auth.com/copenhagen)
- [Lucia Documentation](https://lucia-auth.com/)
- [Oslo Library](https://github.com/pilcrowonpaper/oslo)
- [OWASP Authentication](https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html)

### Getting Help

- **Questions**: Open a [GitHub Discussion](https://github.com/thomasfosterau/effect-auth/discussions)
- **Bugs**: Open a [GitHub Issue](https://github.com/thomasfosterau/effect-auth/issues)
- **Security**: See [SECURITY.md](./SECURITY.md)

### Community

- Be respectful and constructive
- Help others when you can
- Share your knowledge
- Learn from feedback

## License

By contributing to effect-auth, you agree that your contributions will be licensed under the ISC License.

---

Thank you for contributing to effect-auth! 🎉
