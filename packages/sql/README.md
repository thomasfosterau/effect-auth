# @thomasfosterau/effect-auth-sql

Driver-agnostic SQL storage layers for effect-auth, built on effect/sql.

## Install

```bash
pnpm add @thomasfosterau/effect-auth-sql @thomasfosterau/effect-auth effect
```

`effect` is a peer dependency (`>=4.0.0-rc.118`). Add the `SqlClient` driver for your database alongside it (for example `@effect/sql-pg` at the same version as `effect`).

## Usage

```typescript
import { Effect, Layer } from "effect";
import type { SqlClient } from "effect/sql";
import * as Auth from "@thomasfosterau/effect-auth";
import * as AuthSql from "@thomasfosterau/effect-auth-sql";

// `SqlLive` is any layer providing `SqlClient` (pg, sqlite, D1, ...).
export const makeAuth = (SqlLive: Layer.Layer<SqlClient.SqlClient>) => {
  // Creates the `auth_*` tables; idempotent, so it is safe on every deploy.
  const migrate = AuthSql.migrate.pipe(Effect.provide(SqlLive));

  const sessionConfig: Auth.SessionConfig = {
    sessionExpiresIn: { activePeriod: 30 * 86_400_000, idlePeriod: 14 * 86_400_000 },
  };
  const AuthLive = Auth.SessionService.layer(sessionConfig).pipe(
    Layer.provideMerge(Layer.mergeAll(AuthSql.layer, Auth.Hooks.Default)),
    Layer.provide(SqlLive),
  );
  return { migrate, AuthLive };
};
```

## API

- `layer` provides every SQL-backed store at once on top of the ambient `SqlClient`: sessions, users, identifiers, email and password, password reset, email verification, email OTP, magic links, rate limits, WebAuthn challenges and credentials, OAuth state, accounts and users, multi-factor and pending multi-factor, account lockout, API keys and admin.
- Each store also has its own `make*Store` effect and `*StoreLayer` (for example `makeSessionStore` / `SessionStoreLayer`), for wiring a subset.
- `migrate` runs `schemaStatements`, the ordered `CREATE TABLE IF NOT EXISTS` DDL for the `auth_`-prefixed tables.
- Authorization isn't bundled: wire `RbacEntityResolverLayer` and `readRbacPolicies` into an `Authorizer` yourself.

Stores added to the core later (one-time tokens, trusted devices, phone OTP, organizations, the OIDC provider, SSO, device authorization) aren't covered yet: use the `KeyValueStore`-backed layers from the core, or your own.

Storage format: dates are epoch milliseconds (`BIGINT`), booleans `0`/`1`, attribute bags JSON `TEXT`, binary values base64 `TEXT`. Token columns hold the SHA-256 digest computed by the service layer; the database never sees a raw bearer token. Upserts and counters use single `ON CONFLICT … DO UPDATE` / `UPDATE … RETURNING` statements, which PostgreSQL and SQLite support; MySQL isn't supported yet (#260).

## License

MIT
