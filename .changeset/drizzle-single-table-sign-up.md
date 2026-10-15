---
"@thomasfosterau/effect-auth-drizzle": minor
---

Core sign-up works on `SingleTableIdentifierStore` with a `NOT NULL` `email` column: core passes the address to the application's `createUser` as `input.identifier`, the application's writer inserts the row holding it, and the claim that follows finds the address on the row and writes nothing more. On a nullable column the writer may also leave the address out, and the claim writes it. The module docs and README describe the writer's part, with an example (#380).
