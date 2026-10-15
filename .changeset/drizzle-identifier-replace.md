---
"@thomasfosterau/effect-auth-drizzle": minor
---

Both drizzle identifier stores implement `IdentifierStore.replace`, on PostgreSQL, SQLite and MySQL. The default store reads the identifier it replaces, inserts the new one, then deletes the old one; it opens no transaction of its own, so on a handle inside the application's transaction the two writes commit together, and otherwise a failure between them leaves the user holding both, never neither. `SingleTableIdentifierStore` rewrites the row in one `UPDATE users SET email, email_verified[, email_verified_at] WHERE id = <user> AND email = <old>`, on nullable and `NOT NULL` columns alike, keeping the user's id and creation time as the identifier's; a stale call writes nothing and resolves to `null`. Core email change works on both stores (#381).
