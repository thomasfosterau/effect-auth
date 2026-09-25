---
"@thomasfosterau/effect-auth-drizzle": patch
---

Pin that the stores join an application's own drizzle Effect transaction (#181): inside
`db.transaction(tx => …)` on `drizzle-orm/effect-postgres`, every store query — direct and batched
through `Requests` — resolves its handle and runs on the transaction's own fiber, so it sees the
transaction's uncommitted writes and commits or rolls back with it, with no service capture of the
kind the applications' Better Auth adapter needed. Documented in the README.
