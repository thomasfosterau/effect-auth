---
"@thomasfosterau/effect-auth-sql": minor
---

Add `makeApiKeyStore`/`ApiKeyStoreLayer` and `makeAdminUserStore`/`AdminUserStoreLayer`, closing the two SQL storage gaps blocking the API-key and admin planes.

- **`ApiKeyStore`** backs a new `auth_api_keys` table. Every core field round-trips, including `permissions`/`metadata` (JSON), the refill quota fields, and the optional per-key `rateLimit`; `key_hash` carries a unique index for `getByHash` lookups and, like every other bearer-token column in this schema, is the only form of the key ever persisted.
- **`AdminUserStore`** reuses `auth_users` (via the same `userQueries` helpers as `EmailPasswordStore`) for `createUser`/`setPasswordHash`, and resolves `listUsers`'s `searchEmail` against each user's earliest `auth_identifiers` email record — matching, sorting, and paginating in memory, mirroring the reference semantics in core's `Admin.test.ts`.

Both are now included in the aggregate `layer` export and `migrate`'s schema statements.
