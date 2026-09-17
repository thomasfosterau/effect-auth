---
"@thomasfosterau/effect-auth-drizzle": minor
---

Bind the drizzle stores to Effect-shaped drivers, and let the application own the handle's
lifetime (#181).

- **Effect drivers.** `.execute()` returns a `Promise` on the classic drivers and an `Effect`
  on drizzle's Effect drivers (`drizzle-orm/effect-postgres`, `effect-pglite`,
  `effect-mysql2`, `effect-sqlite-*`, new in drizzle `1.0`). `DrizzleResult` is now the union
  of the two and the store layer adapts at runtime, so an Effect-shaped handle reaches the
  database with no Promise round trip anywhere between `Auth.SessionStore` and the driver.
  `effectDatabaseLayer` is the door for those handles; it checks the shape of the builder
  chain structurally, because drizzle's Effect entrypoints only exist from `1.0` and this
  package's peer range starts at `0.44`.
- **Late-bound handles.** `databaseLayer` and `effectDatabaseLayer` now accept an
  `Effect` yielding a handle as well as a handle. The `Effect` is run once per query, in the
  calling fiber, so a connection held in a `Context.Reference` follows the request that set
  it — what a request-scoped pool needs on Cloudflare Workers, where a pool's sockets are
  pinned to the request that opened them. No `AsyncLocalStorage`: the request scope is the
  Effect context.

Passing a plain handle still pins it for the life of the layer, and every existing
`databaseLayer(db)` call keeps working unchanged. The one breaking type change is the
`DrizzleDatabase` service shape, which is now `{ database: Effect<AuthDatabase> }` rather
than `AuthDatabase` — only code that built the layer by hand with
`Layer.succeed(DrizzleDatabase, db)` is affected.
