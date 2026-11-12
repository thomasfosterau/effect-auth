---
"@thomasfosterau/effect-auth-drizzle": minor
---

Drop drizzle-orm 0.4x: the `drizzle-orm` peer range is now `>=1.0.0-rc.5 <2`, and the published declarations are built against drizzle-orm 1.0 (#735). Before, the `.d.ts` was emitted against 0.45, so on 1.0 the exported tables (`Pg.identifiersTable` and the rest) failed `defineSchema`'s column mapping and the application's own queries, and `databaseLayer` named database classes 1.0 does not export, so it accepted anything. `databaseLayer` now takes 1.0's `PgAsyncDatabase`, `SQLiteAsyncDatabase` and `MySqlAsyncDatabase` (and the transaction handles that extend them), and the row and insert types read through `InferSelectModel` / `InferInsertModel`. Applications on 0.44 or 0.45 stay on 0.2.x, or move to drizzle-orm 1.0.
