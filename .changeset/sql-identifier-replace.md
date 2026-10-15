---
"@thomasfosterau/effect-auth-sql": minor
"@thomasfosterau/effect-auth-alchemy": minor
---

The SQL `IdentifierStore` implements `replace`: it inserts the new identifier and deletes the old one inside `sql.withTransaction`, so a value another user holds is refused by the `(type, value)` unique index and the transaction rolls back with the old identifier in place. On Cloudflare D1 (`@thomasfosterau/effect-auth-alchemy`), which has no transactions, the two statements autocommit in the same order, so a failure between them leaves the user holding both identifiers, never neither, and confirming an email change again releases the old one (#381).
