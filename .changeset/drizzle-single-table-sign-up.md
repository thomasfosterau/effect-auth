---
"@thomasfosterau/effect-auth-drizzle": patch
---

`SingleTableIdentifierStore`'s module docs and the README describe core sign-up on a `NOT NULL` `email` column: core passes the address to the application's `createUser` as `input.identifier`, the application's writer inserts the row holding it and reports `created: true`, and the claim that follows finds the address on the row and writes nothing more. On a nullable column the writer may also leave the address out, and the claim writes it. The README gives a writer for each column shape, both compiled and run in the package's tests (#380, #406).
