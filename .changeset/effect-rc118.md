---
"@thomasfosterau/effect-auth": minor
"@thomasfosterau/effect-auth-argon2": minor
"@thomasfosterau/effect-auth-client": minor
"@thomasfosterau/effect-auth-drizzle": minor
"@thomasfosterau/effect-auth-resend": minor
"@thomasfosterau/effect-auth-saml": minor
"@thomasfosterau/effect-auth-sql": minor
"@thomasfosterau/effect-auth-twilio": minor
---

**Breaking:** move to Effect `4.0.0-rc.118`.

Every package above now requires `effect >=4.0.0-rc.118` (was `>=4.0.0-rc.113`). Consumers must upgrade `effect` and every `@effect/*` companion to rc.118 alongside this release. rc.118 removed the `effect/unstable/*` module paths, so the published `dist/` imports the new paths (`effect/http-api`, `effect/http`, `effect/sql`, `effect/persistence`, `effect/process`, and so on) and cannot load on rc.117 or earlier.

- `protectedField` now uses `SchemaGetter.transformOptionalEffect` only; the rc.113 to rc.115 `SchemaGetter.onSome` fallback is gone with the old floor. Behaviour is unchanged.
- `vp run check:dist` now installs the packed packages beside rc.118 by default.
- **An empty encryption secret disables encryption.** On rc.118 an empty environment variable is read as absent, so `JWT_ENCRYPT_PRIVATE_KEY_SECRET=""`, `OAUTH_ENCRYPT_TOKENS_SECRET=""` and `TWO_FACTOR_ENCRYPT_SECRET=""` now resolve to no secret and the private keys, OAuth tokens and TOTP secrets are stored **unencrypted**, with no error. Check that these variables are non-empty wherever you rely on encryption at rest. This release pins the behaviour with tests and does not change it; whether it should fail loudly is tracked in #252. Empty `JWT_ISSUER` and `TRUSTED_DEVICE_SECRET` fail as missing, and an empty `TRUSTED_DEVICE_MAX_AGE_MS` uses its default.
- `@thomasfosterau/effect-auth-alchemy` is **not** part of this change: alchemy 2.0.0-beta.79 still imports `effect/unstable/*`. The package is held `"private": true` (neither versioned nor published) with its `effect >=4.0.0-rc.115` peer floor until alchemy ships an rc.118 build (tracked in #250).
