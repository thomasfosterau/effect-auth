---
"@thomasfosterau/effect-auth-alchemy": minor
---

Postgres over Hyperdrive, alongside D1 (#184). The new `@thomasfosterau/effect-auth-alchemy/postgres` entry provides every effect-auth store over a Cloudflare Hyperdrive binding (`Postgres.layer(env.HYPERDRIVE)`), plus `migrate`, `purgeExpired` and `clientLayer`, all through `@effect/sql-pg`. `@effect/sql-pg` is a new optional peer that only this entry needs. `AuthSchemaProvider` now also reconciles Postgres databases: pass `Postgres.database(url)`, or `postgresDatabase(layer)` over any Postgres `SqlClient` layer, wherever it took a D1 binding, alone or registered by name beside D1 bindings.
