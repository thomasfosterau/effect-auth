---
"@thomasfosterau/effect-auth": minor
---

**Security hardening (#669), breaking:** no hook ever sees a raw session token. `beforeValidateSession` and `beforeSignOut` now receive the session's stored id, `hashToken(token)` (the SHA-256 digest `session.id` already carries), instead of the token the client presented, so a plugin can no longer read, log or forward the credential. This completes #581, which moved every response body, cache cookie and after-hook to the stored id.

- **Both hooks are observe-or-deny.** A plugin refuses the validation or the sign-out by failing, as before. What the hook returns is no longer read back: `SessionService.validateSession` and `invalidateSession` look up and delete the session the presented token names, so a hook cannot rewrite the token or redirect the operation to another session.
- **Migrating a plugin:** compare `ref.sessionId` with `session.id` (or `hashToken(token)`), not with the cookie value. A plugin that rewrote the token has no replacement; validate a different credential before calling the service instead.
