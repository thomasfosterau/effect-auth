---
"@thomasfosterau/effect-auth-alchemy-cloudflare": minor
"@thomasfosterau/effect-auth-alchemy-postgres": patch
---

Rebuild `@thomasfosterau/effect-auth-alchemy-cloudflare` on `@alchemy.run/cloudflare`'s D1 services (ADR-0023). `D1Client`, `layer`, `migrate` and `purgeExpired` take the `QueryDatabaseClient` that `Cloudflare.D1.QueryDatabase(database)` binds, and need the event's `RuntimeContext`; the structural `D1Database`, `D1PreparedStatement` and `D1Result` types are removed. A transaction is sent to D1 as `batch()`es, so the stores' multi-step writes between two reads now commit atomically. `AuthSchema(id, database)` is now an Alchemy Action over a `Cloudflare.D1.Database` (provide `Cloudflare.D1.QueryDatabaseLocal` on deploy); `AuthSchemaProvider`, `AuthSchemaProps`, `AuthSchemaProviderOptions`, `AuthSchemaDatabase`, `DEFAULT_DATABASE`, `UnknownDatabaseError` and `dropOnDelete` are removed. `@thomasfosterau/effect-auth-alchemy-postgres`'s `AuthSchema` doc comment now describes the D1 counterpart as an Action.
