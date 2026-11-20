---
"@thomasfosterau/effect-auth": minor
"@thomasfosterau/effect-auth-drizzle": minor
---

Slide a session's expiry atomically. **Breaking for bring-your-own `SessionStore`s:** the contract gains a required `touch(sessionId, { lastActivityAt, expiresAt })`, which sets those two fields, and nothing else, on a session that still exists and has not expired at `lastActivityAt`, and returns the stored session, or `null` when none matched. `SessionService.validateSession` now refreshes through it instead of writing the whole session back from its read. Before this, the refresh undid a concurrent change to the session's attributes (an organization switch, an elevation), and a store whose `update` upserts brought back a session signed out meanwhile. A session revoked between the read and the refresh is now refused with `SessionNotFoundError`. `SessionTouch` is exported.

`./sql` implements `touch` as one `UPDATE … WHERE … RETURNING`, and the memory stores in `./testing` implement it too. `sessionStoreConformance` gains cases for it.

effect-auth-drizzle's `SessionStore` implements `touch` as one guarded `UPDATE`, then reads the row back when the driver's affected-row count shows a match, so it needs no `RETURNING` on MySQL. On MySQL that count must be the matched rows, which is mysql2's default.
