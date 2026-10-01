---
"@thomasfosterau/effect-auth": minor
"@thomasfosterau/effect-auth-alchemy": minor
"@thomasfosterau/effect-auth-argon2": minor
"@thomasfosterau/effect-auth-client": minor
"@thomasfosterau/effect-auth-drizzle": minor
"@thomasfosterau/effect-auth-resend": minor
"@thomasfosterau/effect-auth-saml": minor
"@thomasfosterau/effect-auth-sql": minor
"@thomasfosterau/effect-auth-twilio": minor
---

Move to effect `4.0.0-rc.112`.

Every package now requires `effect >=4.0.0-rc.112` (raised to `>=4.0.0-rc.113` by the next entry, which fixes the import crash on rc.113 and later); the previous floor was `>=4.0.0-beta.93`. Consumers must upgrade effect alongside this release, because the rc line renamed API this library's public surface is built on.

What the upgrade touched here:

- `Schema.TaggedErrorClass` is now `Schema.TaggedError`, and `Schema.ErrorClass` is now `Schema.Error`. The HTTP error schemas are declared with these, so the rename propagates through every endpoint's `error` list.
- `SchemaIssue.Forbidden` takes its annotations first and the offending value as a plain input rather than an `Option`; `protectedField`'s deny path is updated to match.
- No behaviour of the core library changed as part of the migration.

**Breaking — `@thomasfosterau/effect-auth-alchemy`:** the D1 binding moves from `AuthSchema` props to `AuthSchemaProvider`. Alchemy persists resource props as plain data and replays them on destroy, so a live binding passed as a prop was already gone by the time `delete` ran, and `dropOnDelete: true` would fail on any real `alchemy destroy` — not just under test. Mount the provider with the binding instead — `AuthSchemaProvider({ database: db })`, or `AuthSchemaProvider({ databases: { primary, tenants } })` for several — and declare the resource with plain data only: `AuthSchema("auth-schema", { dropOnDelete: true })`, using `database: "tenants"` to select a named binding. The provider must stay registered with its binding for destroys as well as deploys; a resource naming a database the provider does not hold now fails with the new `UnknownDatabaseError` rather than silently skipping the drop. New exports: `AuthSchemaProviderOptions`, `UnknownDatabaseError`, `DEFAULT_DATABASE`. Because the provider layer is built in `Alchemy.Stack`'s `providers` field, the D1 handle must be obtainable outside the program body — the same shape as alchemy's own providers taking credentials at registration.

This package also moves to `alchemy >=2.0.0-beta.75` (tested against `2.0.0-beta.76`). The `<2.0.0-beta.62` peer cap from the previous release is removed: it existed only because those versions require the rc line of effect, which this release now targets.
