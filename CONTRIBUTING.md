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

- **Bun**: Version 1.2+ recommended
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
   bun install
   ```

4. **Verify setup**:
   ```bash
   bun run build  # Should compile successfully
   bun run test   # Should pass all tests
   ```

### Project Structure

```
effect-auth/                       # Bun workspaces monorepo (Nx task runner, Vite+ toolchain)
├── packages/
│   ├── effect-auth/               # Core library
│   │   └── src/
│   │       ├── Types.ts           # Core domain types (schema'd User, Session, ...)
│   │       ├── Errors.ts          # Shared tagged error definitions
│   │       ├── Password.ts        # Password hashing (PBKDF2, scrypt, multi-algorithm)
│   │       ├── Session.ts         # Session stores + SessionManager
│   │       ├── Authorization.ts   # Authorization/permissions (+ Rbac, Permission, Scope)
│   │       ├── <Feature>.ts       # One module per feature (EmailPassword, WebAuthn, ...)
│   │       ├── Hooks.ts           # Hooks/plugin system
│   │       ├── plugins/           # First-party hooks plugins
│   │       ├── Http*.ts           # HTTP contract, server handlers, typed client
│   │       ├── index.ts           # Public API barrel (the only entry point)
│   │       └── *.test.ts          # Tests alongside source
│   ├── client/                    # @effect-auth/client (browser + React/Svelte/Vue)
│   ├── sql/                       # @effect-auth/sql storage layers
│   ├── argon2/                    # @effect-auth/argon2 hasher
│   ├── alchemy/                   # @effect-auth/alchemy (Cloudflare D1 + IaC)
│   ├── workos/                    # @effect-auth/workos SDK bindings
│   └── siwe/                      # @effect-auth/siwe verifier
├── examples/                      # Example apps
├── site/                          # Starlight docs site (generated API reference)
├── README.md                      # Project overview
├── ARCHITECTURE.md                # Architecture documentation
├── DESIGN.md                      # Settled API conventions & decision record
├── SECURITY.md                    # Security policy
└── CONTRIBUTING.md                # This file
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
   bun run build  # Ensure it compiles
   bun run test   # Ensure tests pass
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

1. **Define shared types** in `packages/effect-auth/src/Types.ts` (module-specific types live in the module)
2. **Define errors** in `packages/effect-auth/src/Errors.ts` if shared, or module-local if only that module raises them
3. **Implement the module** in `packages/effect-auth/src/<Feature>.ts`
4. **Add tests** in the sibling `<Feature>.test.ts` file
5. **Export from** `packages/effect-auth/src/index.ts` (with a one-line doc comment)
6. **Document** in README.md and the site guides

Example: Adding a new password algorithm

1. Read the multi-algorithm guide (`site/src/content/docs/guides/multi-algorithm.md`)
2. Implement the hasher in `packages/effect-auth/src/Password.ts` (or a dedicated package for native deps)
3. Add tests in `Password.test.ts`
4. Document in README.md and the guide

## Testing

### Running Tests

```bash
# Run all tests
bun run test

# Run tests in watch mode
bun run test:watch
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
   bun run changeset
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
   bun run build  # Must compile successfully
   bun run test   # All tests must pass
   bun audit      # Check for vulnerabilities
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

- Password hashing (`packages/effect-auth/src/Password.ts`)
- Session management (`packages/effect-auth/src/Session.ts`, `SessionCookieCache.ts`)
- Cookie flags, CSRF/trusted-origin checks (`packages/effect-auth/src/HttpServer.ts`)
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
