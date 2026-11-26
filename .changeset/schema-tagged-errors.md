---
"@thomasfosterau/effect-auth": minor
"@thomasfosterau/effect-auth-drizzle": patch
"@thomasfosterau/effect-auth-alchemy-postgres": patch
"@thomasfosterau/effect-auth-argon2": patch
---

Every error is now a `Schema.TaggedError` class instead of a `Data.TaggedError`. Tags, fields and `code`s are unchanged, but constructing an error now validates its fields, and each class has a schema you can encode or decode it with. `CloudflareAccessFailure` is now a schema as well as a type.
