---
"@thomasfosterau/effect-auth": minor
"@thomasfosterau/effect-auth-drizzle": minor
"@thomasfosterau/effect-auth-sveltekit": minor
"@thomasfosterau/effect-auth-argon2": minor
"@thomasfosterau/effect-auth-alchemy-cloudflare": minor
"@thomasfosterau/effect-auth-alchemy-postgres": minor
"@thomasfosterau/effect-auth-better-auth": minor
---

**Breaking:** every package follows Effect's export layout. The root barrel re-exports each public module as a PascalCase namespace and nothing flat, and each module is also its own PascalCase subpath.

- `@thomasfosterau/effect-auth`: `Auth.SessionService` becomes `Auth.SessionService.SessionService`, `Auth.User` (the record) becomes `Auth.Types.User`, and `Auth.AuthError` becomes `Auth.Errors.AuthError`. A named import moves to its module's subpath: `import { SessionService } from "@thomasfosterau/effect-auth/SessionService"`.
- The cluster subpaths are PascalCase: `./Email`, `./OAuth`, `./Password`, `./Plugins`, `./MultiFactor` and `./Ladder` replace `./email`, `./oauth`, `./password`, `./plugins`, `./multifactor` and `./ladder`. The subpaths that gate an optional peer or a runtime stay as they are: `./http`, `./client`, `./client/atoms`, `./client/testing`, `./sql`, `./saml`, `./scrypt` and `./testing`.
- `utils` is now the `Normalize` module (`Auth.Normalize.normalizeEmail`).
- Each adapter's root exports one namespace per module, for example `Drizzle.Layers.layer`, `Drizzle.Database.databaseLayer`, `SvelteKit.Handle.handle`, `Argon2.Argon2.argon2Hasher`, `AuthD1.Storage.layer` and `Postgres.Postgres.layer`. Each module is also a subpath (`@thomasfosterau/effect-auth-drizzle/Layers`). better-auth's namespaces were already in this layout and gain their subpaths.
