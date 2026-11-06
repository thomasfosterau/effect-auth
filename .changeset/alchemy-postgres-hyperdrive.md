---
"@thomasfosterau/effect-auth-alchemy-postgres": minor
---

Postgres over Hyperdrive (#184). `@thomasfosterau/effect-auth-alchemy-postgres` provides every effect-auth store over a Cloudflare Hyperdrive binding (`Postgres.layer(env.HYPERDRIVE)`) or a Postgres URL, plus `migrate`, `purgeExpired` and `clientLayer`, all through `@effect/sql-pg`, a required peer. Its `AuthSchema` resource and `AuthSchemaProvider` reconcile the schema in a Postgres database on deploy: pass `database(url)`, or `postgresDatabase(layer)` over any Postgres `SqlClient` layer, alone or registered by name.
