# Security Policy

## Overview

Security is a top priority for effect-auth. This document outlines our security practices, how to report vulnerabilities, and the security guarantees this library provides.

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 1.x     | :white_check_mark: |

## Security Guarantees

### What We Guarantee

effect-auth follows industry best practices from **Lucia**, **Copenhagen Book**, **Oslo**, and **OWASP** to provide:

1. **Secure Password Hashing**:
   - PBKDF2-SHA256 with 210,000+ iterations (OWASP 2023 recommended)
   - Cryptographically secure random salts (16+ bytes)
   - Timing-safe comparison for password verification
   - No plaintext password storage

2. **Secure Session Management**:
   - Cryptographically secure session IDs (160+ bits entropy)
   - Automatic session expiration (active and idle timeouts)
   - Session renewal mechanism
   - Secure session invalidation

3. **Timing Attack Protection**:
   - Password verification uses `crypto.timingSafeEqual` for constant-time comparison
   - Other security-sensitive comparisons (including session handling) may depend on your storage and application logic; you should implement timing-safe comparisons where appropriate

4. **Input Validation**:
   - All inputs are validated before processing
   - Type checking on all security-sensitive operations
   - Clear error messages without information leakage

### What We Don't Guarantee

This library is a **generic authentication framework** that requires you to implement:

1. **Storage Backend**: You must provide secure storage implementations
2. **Transport Security**: You must use HTTPS in production
3. **Cookie Security**: You must set secure cookie flags (HttpOnly, Secure, SameSite)
4. **CSRF Protection**: You must implement CSRF protection
5. **Rate Limiting**: You must implement rate limiting on authentication endpoints
6. **Account Lockout**: You must implement account lockout after failed attempts

## Reporting a Vulnerability

### How to Report

**DO NOT** open a public issue for security vulnerabilities.

Please report security vulnerabilities via GitHub Security Advisories:
https://github.com/thomasfosterau/effect-auth/security/advisories/new

### What to Include

Please include the following in your report:

1. **Description**: Detailed description of the vulnerability
2. **Impact**: What an attacker could do with this vulnerability
3. **Reproduction**: Step-by-step instructions to reproduce the issue
4. **Proof of Concept**: Code or commands demonstrating the vulnerability (if applicable)
5. **Affected Versions**: Which versions are affected
6. **Suggested Fix**: If you have suggestions for how to fix it (optional)

### Response Timeline

- **Initial Response**: Within 48 hours
- **Triage**: Within 1 week
- **Fix Timeline**: Depends on severity
  - Critical: Within 7 days
  - High: Within 30 days
  - Medium: Within 90 days
  - Low: Next release cycle

### Disclosure Policy

We follow **responsible disclosure**:

1. Security issues are fixed privately
2. Fixes are released as soon as possible
3. Public disclosure happens after:
   - A fix is available
   - Users have had time to upgrade (typically 30 days)
   - Or by mutual agreement with the reporter

## Security Best Practices for Users

### Implementation Requirements

When implementing effect-auth in your application, you **MUST**:

1. **Use HTTPS**: Always use HTTPS in production
   - Never transmit session tokens over HTTP
   - Use HSTS headers

2. **Secure Cookies**: Set proper cookie flags

   ```typescript
   {
     httpOnly: true,      // Prevent JavaScript access
     secure: true,        // HTTPS only
     sameSite: "lax",     // CSRF protection
     path: "/",
     maxAge: 60 * 60 * 24 * 30  // 30 days
   }
   ```

3. **CSRF Protection**: Implement CSRF tokens
   - Use synchronizer tokens
   - Or double-submit cookies
   - See [Copenhagen Book on CSRF](https://lucia-auth.com/copenhagen)

4. **Rate Limiting**: Implement rate limiting
   - Limit login attempts per IP
   - Limit login attempts per username
   - Use exponential backoff

5. **Account Lockout**: Implement account lockout
   - Lock after N failed attempts
   - Require CAPTCHA or email verification to unlock
   - Log lockout events

6. **Secure Storage**: Use secure storage backends
   - Use encrypted connections to databases
   - Store session data securely (Redis, PostgreSQL with encryption)
   - Never log session tokens or passwords

7. **Input Validation**: Validate all user inputs
   - Validate email formats
   - Validate username formats
   - Sanitize inputs before database queries
   - Use parameterized queries

8. **Logging**: Log security events without leaking sensitive data
   - Log authentication failures
   - Log permission denials
   - **Never log**: passwords, session tokens, API keys
   - Log timing-safe (don't log before validation)

### Password Requirements

Enforce strong password requirements in your application:

1. **Minimum Length**: 12+ characters recommended
2. **Complexity**: Consider using entropy measurements instead of character class requirements
3. **Breach Detection**: Check against known breached passwords (e.g., Have I Been Pwned API)
4. **No Common Passwords**: Block dictionary words and common passwords
5. **Password Strength Meter**: Provide real-time feedback to users

See [OWASP Password Storage Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html)

### Session Management

Follow **Copenhagen Book** guidelines for session management:

1. **Session Lifetime**:
   - Active period: 30 days maximum recommended
   - Idle period: 14 days maximum recommended
   - Adjust based on your security requirements

2. **Session Renewal**:
   - Renew sessions on activity
   - Consider rotating session IDs on privilege escalation

3. **Session Invalidation**:
   - Provide "logout" functionality
   - Provide "logout all devices" functionality
   - Invalidate sessions on password change
   - Invalidate sessions on security events

4. **Session Storage**:
   - Use Redis or similar for high-performance session storage
   - Set TTL on session records
   - Clean up expired sessions regularly

### Multi-Factor Authentication (MFA)

While effect-auth doesn't currently include MFA primitives, you should consider:

1. **TOTP**: Time-based One-Time Passwords (Google Authenticator, Authy)
2. **WebAuthn**: Hardware security keys (YubiKey, built-in biometrics)
3. **SMS**: Only as a last resort (vulnerable to SIM swapping)
4. **Backup Codes**: For account recovery

See [Oslo library](https://github.com/pilcrowonpaper/oslo) for MFA primitives.

## Known Security Considerations

### Timing Attacks

**Mitigated**: Constant-work sign-in and timing-safe comparisons prevent user enumeration.

- Password verification: ✓ Timing-safe (`crypto.timingSafeEqual` inside the hasher)
- Sign-in constant work: ✓ A decoy hash is derived from the active `PasswordHasher` at
  service construction. Every sign-in attempt — whether the account exists or not —
  calls `passwordHasher.verify` against either the real stored hash or the decoy,
  so the observable response time does not reveal account existence.
- Session validation: ✓ Timing-safe
- Token comparison: ✓ Timing-safe

### Brute Force Attacks

**User Responsibility**: Implement rate limiting and account lockout

- effect-auth provides secure password hashing (210,000 iterations)
- You must implement rate limiting on authentication endpoints
- You must implement account lockout after failed attempts

### Session Fixation

**Mitigated**: Session IDs are generated cryptographically

- New session ID on every `createSession` call
- You should regenerate session on privilege escalation
- You should invalidate old session after login

### Session Hijacking

**Partially Mitigated**: Session IDs are cryptographically secure

- Session IDs have 160+ bits entropy
- You must use HTTPS to prevent interception
- You must set HttpOnly cookie flag
- You must implement session timeout

### Password Storage

**Mitigated**: PBKDF2-SHA256 with OWASP-recommended iterations

- PBKDF2-SHA256 with 210,000 iterations
- Cryptographically secure random salts
- Timing-safe verification
- Support for algorithm upgrades (see `docs/MULTI_ALGORITHM.md`)

### SQL Injection

**User Responsibility**: Use parameterized queries in your storage implementations

- effect-auth doesn't interact with databases directly
- You must use parameterized queries in your `SessionStore` and `UserStore` implementations

### XSS (Cross-Site Scripting)

**User Responsibility**: Sanitize outputs and set proper headers

- Use HttpOnly cookies to prevent session token theft
- Sanitize user-generated content
- Use Content Security Policy (CSP) headers

### CSRF (Cross-Site Request Forgery)

**User Responsibility**: Implement CSRF protection

- Use SameSite cookie attribute
- Implement CSRF tokens
- See [Copenhagen Book on CSRF](https://lucia-auth.com/copenhagen)

## Security Testing

### Automated Testing

Our test suite currently includes:

- Password hashing security tests
- Session expiration tests

Run tests with: `bun run test`

### Manual Security Review

Before each release, we perform:

- Code review of all security-sensitive changes
- Dependency vulnerability scanning (`bun audit`)
- Review of error messages for information leakage
- Review of logging for sensitive data

### External Security Audits

We welcome security researchers to audit this library. Please report any findings through our vulnerability disclosure process.

## Dependency Security

### Monitoring

We monitor dependencies for known vulnerabilities:

- `bun audit` is run regularly
- GitHub Dependabot alerts are enabled
- Security patches are prioritized

### Minimal Dependencies

effect-auth has minimal runtime dependencies:

- **effect**: Core Effect library (required)

This minimizes the attack surface from third-party code.

### Updating Dependencies

Security updates to dependencies are released as:

- **Patch releases** for Effect versions
- **Documented** in release notes
- **Tested** with full test suite

## Compliance and Standards

### Standards We Follow

- **OWASP Top 10**: We address relevant OWASP vulnerabilities
- **OWASP ASVS**: Authentication Security Verification Standard
- **OWASP Password Storage**: Hashing algorithm and parameter recommendations
- **Copenhagen Book**: Session management best practices
- **Oslo**: Cryptographic primitive implementations

### Audit Trail

Security-relevant changes are:

- Documented in commit messages
- Reviewed by maintainers
- Tested comprehensively
- Announced in release notes

## Security Updates

### How We Notify Users

Security updates are announced through:

1. **GitHub Security Advisories**
2. **Release Notes** (marked as security release)
3. **NPM Package Updates** (with security notice)

### Update Recommendations

When a security update is released:

1. **Read the advisory**: Understand the vulnerability
2. **Update immediately**: Run `bun update effect-auth`
3. **Review your code**: Check if you're affected
4. **Test thoroughly**: Run your test suite
5. **Deploy quickly**: Deploy to production as soon as possible

## Additional Resources

### Security Documentation

- [OWASP Authentication Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html)
- [OWASP Password Storage Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html)
- [OWASP Session Management Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html)
- [The Copenhagen Book](https://lucia-auth.com/copenhagen)
- [Lucia Security Considerations](https://lucia-auth.com/)

### Related Projects

- [Lucia](https://lucia-auth.com/) - Authentication library
- [Oslo](https://github.com/pilcrowonpaper/oslo) - Authentication primitives
- [Effect](https://effect.website/) - TypeScript effect system

## Contact

For security-related questions or concerns, please contact:

**[MAINTAINER EMAIL]** (To be filled by repository maintainer)

For general questions, please use GitHub Issues:
https://github.com/thomasfosterau/effect-auth/issues

---

**Last Updated**: 2026-02-07
**Version**: 1.0.0
