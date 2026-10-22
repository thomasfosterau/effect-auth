# @thomasfosterau/effect-auth-drizzle

`SessionStore`, `UserStore` and `IdentifierStore` (plus a single-table `IdentifierStore`) over Drizzle ORM for PostgreSQL, SQLite and MySQL, batched `Request` reads, and drizzle renderings of two kernel projections (`ladderCheck`, `ownedListFilter`).

## Boundary

Archetype **Storage adapter** (`.fallowrc.json` zone `storage-adapters`, which may import `core` and `ladder`). Peers: `effect` and `drizzle-orm` (`catalog:peers`, floor `>=0.44.0`), `@types/pg` optional. Depends on `@thomasfosterau/effect-auth`. The package never opens a connection and bundles no driver: the consumer hands over a drizzle handle through `databaseLayer` / `effectDatabaseLayer`. `drizzle-orm-effect` (the aliased 1.0 prerelease), PGlite, `better-sqlite3` and `pg` are dev dependencies for the suites only. It stands alone: it does not wrap effect-auth-sql.

## Invariants

- **One store implementation serves all three dialects.** It uses only the query-builder fragment `PgDatabase`, `BaseSQLiteDatabase` and `MySqlDatabase` spell identically (`AuthDatabase` in `Database.ts`), each call ending in `.execute()`. No `RETURNING` (MySQL has none): `setVerified` updates, then re-reads.
- **No `any` in the public surface**: row and insert types derive from the tables passed in; `defineSchema` checks column mappings at the type level (`ColumnKey`).
- **Promise and Effect drivers are one code path.** A query's result is `Promise<A> | Effect<A>`; the stores run in the caller's fiber, so an application's `db.transaction` on an Effect driver covers every store call (`Transaction.test.ts`). A handle may be an `Effect` that yields it, run once per query, for request-scoped pools (required on Workers).
- **Store contract**: a miss is `null`, a delete of a missing row is a no-op, a driver failure (unique violation included) is `AuthError` with the cause. Core's `claimIdentifier` / `replaceIdentifier` turn the race into `IdentifierTakenError`.
- **`(type, value)` is unique** on the identifiers table; `IdentifierStore.replace` claims the new value before deleting the old one and opens no transaction of its own.
- **Session ids are token digests** computed by the service; `UserStore` never reads or writes `password_hash`.
- **`migrationStatements` / `migrationSql` match the drizzle tables** per dialect (`*Schema.test.ts`); MySQL declares indexes inline (no `CREATE INDEX IF NOT EXISTS`) and uses `varchar(255)` so the unique index is legal.
- **Batched reads keep store semantics** (dedupe, coalesce into one `IN (...)`, `null` on a miss, identifiers ordered by `createdAt`), and the store contracts never use them. `Requests.test.ts` pins query counts through drizzle's `logger`.
- **`ownedListFilter` agrees with `Auth.OwnedAccess.canView`** row for row (`OwnedListFilter.test.ts`, on Postgres); the follow set stays a subquery and an unrenderable one fails closed.
- **The README's sign-up writers are compiled and run**: `src/testing/readme/*Writer.ts` hold them between `README:begin` / `README:end` markers, and `ReadmeSignUpWriter.test.ts` checks the README shows each verbatim. Edit both together.

## Terms

- **Dialect namespace** — `Pg`, `Sqlite`, `MySql`: `tables`, `defineTables(names)`, `migrationStatements`, `migrationSql`.
- **Auth schema** — `defineSchema({ sessions, users, identifiers })`: the stores pointed at an application's own tables by column mapping; `fromTables` is the identity mapping.
- **Promoted attribute** — a user attribute kept as a real column (`users.role`), surfaced in `user.attributes` under its name; the column is the only authority for that key.
- **Single-table identifiers** — `SingleTableIdentifierStore`: one email per user, read from and written to the application's `users` row.
