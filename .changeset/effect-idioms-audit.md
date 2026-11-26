---
"@thomasfosterau/effect-auth": minor
"@thomasfosterau/effect-auth-argon2": minor
"@thomasfosterau/effect-auth-drizzle": patch
---

Effect idioms audit.

**Breaking:**

- `Authorizer.layer` and `Rbac.layer` fail with the new `Authorizer.PolicyValidationError` (a `Data.TaggedError`) when a policy does not validate, instead of an `AuthError` subclass. Match on `_tag === "PolicyValidationError"` rather than `instanceof AuthError`, and widen a layer's annotated error type to include it.
- The SQL RBAC reads (`readRbacPolicies` and `makeRbacEntityResolver`'s `resolve`) fail with `AuthError` on a database failure instead of dying, so `readRbacPolicies` now has an `AuthError` error channel. Handle it where you build the `Authorizer` from it.
- The Argon2 hashers (`Password.argon2Hasher` and the argon2 package's `argon2Hasher`) throw `Password.Argon2ConfigError` instead of a `RangeError` for a configuration whose hashes would not verify. Catch it by class or by `_tag`.

**Other changes:**

- The argon2 hasher draws salts from a `SecureRandom` service. Its new `random` option takes one, and it defaults to core's Web Crypto `PlatformCrypto.instance`.
- Generated user, identifier and policy-link ids are UUIDv4s from `SecureRandom` rather than `crypto.randomUUID`. They have the same format as before.
