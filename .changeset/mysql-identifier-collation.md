---
"@thomasfosterau/effect-auth-drizzle": minor
"@thomasfosterau/effect-auth": minor
---

Security fix (#602): identifier lookups no longer resolve a different account when the database compares strings loosely.

On MySQL the identifiers table's `value` column used the server's default collation (`utf8mb4_0900_ai_ci` on MySQL 8), which is case-, accent- and width-insensitive. A password reset or magic link requested for a look-alike address such as `bob@exämple.com` (an IDN domain an attacker holds) found `bob@example.com`'s identifier, so the reset token for Bob's account was mailed to the attacker's address. PostgreSQL and SQLite compare bytes and were not affected.

**effect-auth-drizzle (schema change).** `MySql.tables.identifiers.value` is now `VARCHAR(255) CHARACTER SET utf8mb4 COLLATE utf8mb4_bin`, in the drizzle table and in `MySql.migrationStatements` / `migrationSql`, so the lookup and the `(type, value)` unique key compare byte for byte. New exports: `MySql.binaryVarchar(name, { length })`, a `varchar` column under that collation for your own identifier columns; `MySql.identifierCollation` (`"utf8mb4_bin"`); and `MySql.collationMigrationStatements(names?)`, the one-off migration for an existing table. An application's own column the stores look identifiers up in, such as the single-table store's `users.email` or a `defineSchema` value column, needs the same collation on MySQL.

**Migration for existing MySQL deployments.** `migrationSql` is `CREATE TABLE IF NOT EXISTS` and does not change an existing table. Run `MySql.collationMigrationStatements()` once:

```sql
ALTER TABLE effect_auth_identifiers
  MODIFY value VARCHAR(255) CHARACTER SET utf8mb4 COLLATE utf8mb4_bin NOT NULL;
```

The old insensitive unique key already refused values that compared equal under it, so no existing rows collide and the statement cannot fail on duplicates. It rebuilds the table. For the single-table store, run the same `MODIFY` on your `users.email` column (keep its `NULL` / `NOT NULL`). drizzle-kit users get the equivalent migration by regenerating from `MySql.tables` or from a column declared with `binaryVarchar`. PostgreSQL and SQLite deployments need nothing.

**effect-auth (core).** Every service now reads identifiers through the new `lookupIdentifier(store, type, value)`, which treats a record whose `type` or `value` differs from the one asked for as a miss and logs a warning. This covers every store, bring-your-own ones included, and a MySQL table not yet migrated: a look-alike reads as an unknown address. `resolveUserByIdentifier`, `claimIdentifier` and `replaceIdentifier` use it too. A password reset is bound to, stored with and sent to the resolved identifier's own value, and the email-verification resends go to the identifier's value. Behaviour change for a store that compares loosely: a sign-up of a look-alike value now fails on the store's unique index (`AuthError`) instead of reporting `IdentifierTakenError`. `identifierStoreConformance` (`/testing`) gains a case that checks values differing only by case, accent or width are distinct identifiers.

Whether email input is restricted or punycoded is not decided here.
