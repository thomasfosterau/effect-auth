---
"@thomasfosterau/effect-auth": minor
---

Impersonation has guard rails. `AdminService.impersonateUser` takes the actor's session as a third argument and refuses an administrator target unless `AdminConfig.allowImpersonatingAdmins` is set, and refuses to start from a session that is itself an impersonation. `impersonationSessionDuration` is now enforced: `SessionService` caps the session's `expiresAt` at `attributes.impersonationExpiresAt` and refuses it past that deadline, and the layer fails at build when the duration is not finite and positive.

While impersonating, credential and identity changes are refused with the new `ImpersonationForbiddenError` (`IMPERSONATION_FORBIDDEN`; `403` over HTTP): password, email, multi-factor, passkeys, API keys, linked accounts, usernames, identifiers and account deletion. The new `Impersonation` namespace exports `assertNotImpersonating` and `guardCurrentSession` for an application's own operations.

`AdminService.stopImpersonating` ends an impersonation (`DELETE /impersonations/current` goes through it), and the new `afterImpersonationStart` / `afterImpersonationStop` hooks fire when one starts and stops; `AuditPlugin` logs both. `AdminService` now requires `Hooks`.
