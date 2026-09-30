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

Fix the import crash on Effect rc.113 and later, and align the peer range with what the code actually runs on.

The package declared `effect >=4.0.0-rc.112` but still called `Config.string`, `Config.redacted`, `Config.int` and `Config.boolean`, which rc.113 renamed to `Config.String`, `Config.Redacted`, `Config.Int` and `Config.Boolean`. Those `Config`s are built at module load, so importing `@thomasfosterau/effect-auth` (and every package that imports it) threw `TypeError: Config.string is not a function` on every Effect version from rc.113 up.

- **Breaking peer range:** every package now requires `effect >=4.0.0-rc.113` (was `>=4.0.0-rc.112`). rc.112 no longer works, because it lacks the renamed `Config` constructors. Developed and tested against `4.0.0-rc.117`; also smoke-tested from the packed `dist/` on rc.113 through rc.117.
- `protectedField` no longer hard-depends on one getter API. `SchemaGetter.onSome` exists on rc.113 to rc.115 and `SchemaGetter.transformOptionalEffect` on rc.116 and later, so the field picks whichever the installed Effect has when the schema is built. Behaviour is unchanged: an absent value passes through, a present one is authorized, and a denial omits the key or fails the parse.
- **`@thomasfosterau/effect-auth-alchemy`:** the `alchemy` peer floor rises from `>=2.0.0-beta.75` to `>=2.0.0-beta.78`. alchemy beta.75 to beta.77 call `Config.string` themselves and crash at import on rc.113 and later; beta.78 is the first release that works (and requires effect `>=4.0.0-rc.115`, so this package needs at least rc.115 in practice).
- New `vp run check:dist` installs the packed packages beside an exact Effect version (default: the floor) and imports every entry point, and CI runs it, so a stale `dist/` can no longer claim the range.
