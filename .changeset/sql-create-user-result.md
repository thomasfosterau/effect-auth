---
"@thomasfosterau/effect-auth-sql": minor
"@thomasfosterau/effect-auth-alchemy": minor
---

Every SQL `createUser` seam (`EmailPasswordStore`, `OAuthUserStore`, `MagicLinkUserStore`, `EmailOtpUserStore` and `AdminUserStore`) resolves to core's `CreateUserResult`, `{ user, created: true }`: each is a plain `INSERT` with a fresh id, so every success is a new user (#406).
