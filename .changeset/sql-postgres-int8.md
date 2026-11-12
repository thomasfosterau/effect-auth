---
"@thomasfosterau/effect-auth": patch
---

`./sql` store reads failed on a real PostgreSQL server (#766). `@effect/sql-pg` returns a `BIGINT` column as a JavaScript `bigint` and node-postgres as a decimal string, but the stores expected a `number`: session, user and identifier reads failed with `stored instant did not decode`, and the WebAuthn challenge, email verification, rate-limit, OAuth state, API key and other stores handed back `bigint` or string timestamps where their contracts promise a `number`. Every row read now decodes the schema's `BIGINT` columns from a `number`, a `bigint` or a canonical decimal string into a safe integer, and fails with `AuthError` on anything else (no `NaN`, no rounding past `Number.MAX_SAFE_INTEGER`). SQLite, Cloudflare D1 and PGlite were not affected.
