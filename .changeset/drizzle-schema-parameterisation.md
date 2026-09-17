---
"@thomasfosterau/effect-auth-drizzle": minor
---

Let the stores run against tables this package did not define (#182).

`Pg.defineTables()` could rename the three auth tables and nothing else, so an application
adopting effect-auth **in place** — one whose entity graph already has foreign keys into
`users.id`, and whose primary keys are `uuid` rather than `text` — had to migrate its whole
graph to meet this package's schema. `defineSchema` inverts that: it pairs each table with a
mapping from the fields the stores need to the columns _that_ table actually has, and the
stores project through the mapping.

```ts
const stores = layer(
  defineSchema({
    sessions: { table: appSessions, columns: { id: "digest", userId: "account", ... } },
    users: { table: appUsers, columns: { id: "key", name: "displayName", ... } },
    identifiers: { table: appHandles, columns: { id: "key", type: "kind", ... } },
  }),
);
```

The mapping is checked at the application's own call site: `ColumnKey` picks out exactly
those keys of a table whose selected value is assignable to the type the store needs, so
naming a `text` column for `expiresAt`, a non-nullable one for `verifiedAt`, or a column that
does not exist, is a compile error rather than a runtime surprise. Column names are free;
column types are free as long as they read back as the value the domain uses, which is what
makes `uuid` keys a mapping rather than a migration.

Every store factory — `SessionStore.layer`, `UserStore.layer`, `IdentifierStore.layer`,
`Requests.layer` and the aggregate `layer` — now takes `Tables | AuthSchema`, so passing
`Pg.tables`, `Sqlite.tables`, `MySql.tables` or a `defineTables(...)` result works exactly as
before; the fixed-shape path builds the identity mapping and runs the same code. Writes still
cover only the mapped columns, so an application column the stores know nothing about needs a
database-level default. Promoting a named attribute to a real typed column the stores write,
and the single-table `users.email` identifier mode, are the remaining parts of #182.

The one behaviour change on the existing path: reads now project the columns the stores
actually use instead of `SELECT`ing every column of the table, so `effect_auth_users.password_hash`
is no longer fetched by `UserStore`. `AuthDatabase.select` gained a projecting overload for
this, and `DrizzleSelectFrom`/`DrizzleSelectFiltered` are now aliases over row-shaped
`DrizzleRowSelectFrom`/`DrizzleRowSelectFiltered` — same meaning, same type arguments.
