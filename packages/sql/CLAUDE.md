# @thomasfosterau/effect-auth-sql

Driver-agnostic SQL implementations of the core's store contracts over `effect/sql`'s `SqlClient`, plus the `auth_*` DDL and the RBAC tables' resolver and policy reader.

## Boundary

Archetype **Storage adapter** (`.fallowrc.json` zone `storage-adapters`, which may import `core` and `ladder`). Peer: `effect` (`catalog:peers`). Depends on `@thomasfosterau/effect-auth`. No driver is a dependency or a peer: the consumer provides a `SqlClient` layer (`@effect/sql-pg`, `@effect/sql-sqlite-*`, the D1 client in effect-auth-alchemy); the PGlite and `better-sqlite3` drivers are dev dependencies for the suite only. effect-auth-alchemy builds on this package and re-exports nothing of its own schema, so a change to a table or a statement here is a change to every D1 deployment too.

## Invariants

- **Supported dialects are SQLite (D1 included) and PostgreSQL.** Every statement must run on both. MySQL is not supported (#260): it has no `ON CONFLICT`. Don't add per-dialect branches; point MySQL users at effect-auth-drizzle.
- **`schemaStatements` is append-only, idempotent DDL**: one statement per entry, `CREATE TABLE IF NOT EXISTS` / `CREATE [UNIQUE] INDEX IF NOT EXISTS`, `auth_`-prefixed tables, so `migrate` is safe on every deploy and on every cold start. effect-auth-alchemy derives its table list (`authTableNames`) from these statements.
- **Codecs**: instants are epoch milliseconds in `BIGINT` (an `INTEGER` overflows Postgres int4), booleans `0`/`1`, attribute bags JSON `TEXT`, binary values base64 `TEXT`.
- **Token columns hold the digest the service computed** (`auth_sessions.id`, magic-link, verification and reset tokens, `auth_api_keys.key_hash`). The store never hashes and never sees a raw bearer token.
- **Atomicity is per statement**: upserts and counters are a single `ON CONFLICT … DO UPDATE` or `UPDATE … RETURNING`, never read-modify-write. Multi-step writes (challenge, OAuth state, `emailOtp.upsert`, `identifier.replace`) run in `sql.withTransaction`; on D1 that is not atomic (see effect-auth-alchemy), so a multi-step write must stay safe when interrupted between its statements: `identifier.replace` claims the new value before it releases the old one.
- **Store contract**: a miss is `null`; any driver failure becomes `AuthError` with the cause kept; methods carry `R = never` (the `SqlClient` is read when the store is built).
- **Unique indexes are the claim mechanism** (`auth_identifiers (type, value)`, `auth_oauth_accounts (provider, provider_id)`, `auth_api_keys (key_hash)`): a violation surfaces as `AuthError` and core turns it into the domain error.
- **Authorization is not in `layer`**: `RbacEntityResolverLayer` (roles as `Role::` parents of `User::`) and `readRbacPolicies` (compiled by `Auth.Rbac.policies`) are wired into an `Authorizer` by the application. There is no second evaluation path.
- **`layer` covers a fixed store set**; stores added to core later (one-time tokens, trusted devices, phone OTP, organizations, the OIDC provider, SSO, device authorization) are not implemented here yet. Adding one means a table in `Schema.ts`, `make*Store` + `*StoreLayer` in `Stores.ts`, an entry in `layer`, and a run of the shared suite on both engines.

## Terms

- **Store layer** — `<Name>StoreLayer`: `Layer<Auth.<Name>Store, never, SqlClient>` over `make<Name>Store`.
- **RBAC tables** — `auth_user_roles` (user → role) and `auth_role_permissions` (role → `resource`/`action`); data for the kernel, not a store service.
