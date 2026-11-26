---
"@thomasfosterau/effect-auth": minor
---

Bans and SCIM deactivation are enforced in the core, with no plugin to wire. `SessionService.createSession` and `validateSession` fail with `UserBannedError` for a banned (unlapsed) or SCIM-deactivated user, whatever `Hooks` the service was built with, so every sign-in method and every presented session is refused. `AdminService.banUser` and SCIM deactivation (`PATCH active:false`, `DELETE /Users/:id`) now also revoke the user's API keys and the OIDC provider's access and refresh tokens and consents. The session cookie cache always gates `banned`, `banExpires` and `scimDeactivated`, whatever `serverOnlyAttributes` says. `BannedUserPlugin` and `ScimDeactivatedPlugin` are deprecated no-ops; drop them from your hook stack. JWTs already issued still run to their expiry.
