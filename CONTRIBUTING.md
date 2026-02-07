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
   - [AGENT_GUIDELINES.md](./AGENT_GUIDELINES.md) - Coding standards and patterns
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

- **Node.js**: Version 18+ recommended
- **npm**: Version 9+ recommended
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
   npm install --legacy-peer-deps
   ```
   
   Note: `--legacy-peer-deps` is required due to vitest version conflicts.

4. **Verify setup**:
   ```bash
   npm run build  # Should compile successfully
   npm test       # Should pass all tests
   ```

### Project Structure

```
effect-auth/
├── src/                     # Source code
│   ├── types.ts            # Core type definitions
│   ├── errors.ts           # Tagged error definitions
│   ├── password.ts         # Password hashing
│   ├── session.ts          # Session management
│   ├── authorization.ts    # Authorization/permissions
│   ├── requests.ts         # Request definitions
│   ├── resolvers.ts        # RequestResolver implementations
│   ├── index.ts            # Public API exports
│   └── *.test.ts           # Tests alongside source
├── examples/               # Usage examples
├── docs/                   # Additional documentation
├── README.md              # Project overview
├── ARCHITECTURE.md        # Architecture documentation
├── AGENT_GUIDELINES.md    # Development guidelines
├── SECURITY.md            # Security policy
└── CONTRIBUTING.md        # This file
```

## Making Changes

### Before You Start

1. **Create an issue** if one doesn't exist
2. **Discuss the approach** with maintainers
3. **Review [AGENT_GUIDELINES.md](./AGENT_GUIDELINES.md)** for:
   - Security requirements
   - Code patterns
   - Testing requirements
   - Effect patterns

### Development Workflow

1. **Create a branch**:
   ```bash
   git checkout -b feature/your-feature-name
   ```

2. **Make your changes**:
   - Follow existing code style
   - Use Effect patterns (see AGENT_GUIDELINES.md)
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
   npm run build  # Ensure it compiles
   npm test       # Ensure tests pass
   ```

### Code Style

- **TypeScript**: Use strict mode
- **Effect**: Use Effect.gen for composition
- **Naming**: Follow conventions in AGENT_GUIDELINES.md
- **Comments**: Add comments for complex logic or security decisions
- **Formatting**: Follow existing code style

### Security Requirements

**This is critical** - All security-related changes must:

1. **Follow OWASP guidelines**
2. **Use timing-safe comparisons** (`crypto.timingSafeEqual`)
3. **Use cryptographically secure random** (`crypto.randomBytes`)
4. **Validate all inputs**
5. **Never log sensitive data**

See [SECURITY.md](./SECURITY.md) for detailed security requirements.

### Adding New Features

1. **Define types** in `src/types.ts`
2. **Define errors** in `src/errors.ts`
3. **Implement functionality** in appropriate file
4. **Add tests** in `*.test.ts` file
5. **Export from** `src/index.ts`
6. **Document** in README.md

Example: Adding a new password algorithm

1. Read `docs/MULTI_ALGORITHM.md`
2. Implement hasher in `src/password.ts`
3. Add tests in `src/password.test.ts`
4. Document in README.md and MULTI_ALGORITHM.md

## Testing

### Running Tests

```bash
# Run all tests
npm test

# Run tests in watch mode
npm run test:watch
```

### Writing Tests

- **Framework**: Vitest with @effect/vitest
- **Location**: Place tests next to source files (e.g., `password.test.ts` next to `password.ts`)
- **Coverage**: Test happy paths, error cases, edge cases, and security properties

Example test structure:

```typescript
import { describe, it, expect } from "vitest"
import { Effect } from "effect"

describe("MyFeature", () => {
  it("should work correctly", () =>
    Effect.gen(function* () {
      const result = yield* myFunction()
      expect(result).toBe(expected)
    }).pipe(Effect.runPromise))
  
  it("should handle errors", () =>
    Effect.gen(function* () {
      const result = yield* Effect.flip(myFunction())
      expect(result._tag).toBe("MyError")
    }).pipe(Effect.runPromise))
})
```

### Test Requirements

All changes should include:

1. **Unit tests** for new functionality
2. **Error case tests** for error handling
3. **Security tests** for security-sensitive code
4. **Edge case tests** for boundary conditions

## Submitting Changes

### Pull Request Process

1. **Update documentation**:
   - Update README.md if adding/changing features
   - Update ARCHITECTURE.md if changing design
   - Update examples if relevant

2. **Ensure quality**:
   ```bash
   npm run build  # Must compile successfully
   npm test       # All tests must pass
   npm audit      # Check for vulnerabilities
   ```

3. **Push to your fork**:
   ```bash
   git push origin feature/your-feature-name
   ```

4. **Open a Pull Request**:
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

## Security

### Reporting Vulnerabilities

**DO NOT** open public issues for security vulnerabilities.

See [SECURITY.md](./SECURITY.md) for:
- How to report security issues
- Security requirements
- Security best practices

### Security Reviews

All changes to security-sensitive code require:

1. **Security checklist** completion (see AGENT_GUIDELINES.md)
2. **Maintainer review**
3. **Test coverage** for security properties
4. **Documentation** of security decisions

Security-sensitive areas:

- Password hashing (`src/password.ts`)
- Session management (`src/session.ts`)
- Cryptographic operations
- Input validation
- Error handling (avoid information leakage)

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

