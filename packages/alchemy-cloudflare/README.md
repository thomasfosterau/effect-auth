# @thomasfosterau/effect-auth-alchemy-cloudflare

Cloudflare **D1** support for [`@thomasfosterau/effect-auth`](https://github.com/thomasfosterau/effect-auth/tree/trunk/packages/effect-auth) on
[Alchemy v2](https://v2.alchemy.run) — the TypeScript-native, Effect-based
Infrastructure-as-Code toolkit — covering both sides of the deploy:

- **Deploy side** — the [`AuthSchema`](https://github.com/thomasfosterau/effect-auth/blob/trunk/docs/guides/alchemy.md#the-authschema-action) action, so the
  Alchemy engine applies the auth schema to your `Cloudflare.D1.Database` on
  deploy.
- **Runtime side** — [`layer(db)`](https://github.com/thomasfosterau/effect-auth/blob/trunk/docs/guides/alchemy.md#storage-layers), which turns the client
  `Cloudflare.D1.QueryDatabase(database)` binds into every effect-auth store.

It is built on [`@alchemy.run/cloudflare`](https://v2.alchemy.run)'s own D1
services and resources — `Cloudflare.D1.Database`,
`Cloudflare.D1.QueryDatabase`, `Cloudflare.D1.QueryDatabaseLocal` — never on
raw workerd types. It contains no queries and no schema of its own:

| Module       | What it is                                                                             |
| ------------ | -------------------------------------------------------------------------------------- |
| `D1Client`   | A `SqlClient` (from `effect/sql`) over the provider's `QueryDatabaseClient`.           |
| `Storage`    | `layer(db)` / `migrate(db)` / `purgeExpired(db)` — the client wired to the SQL stores. |
| `AuthSchema` | The Alchemy Action that applies the schema on deploy.                                  |

Postgres (over Hyperdrive or a URL) is the sibling package
[`@thomasfosterau/effect-auth-alchemy-postgres`](https://github.com/thomasfosterau/effect-auth/tree/trunk/packages/alchemy-postgres),
whose `AuthSchema` is a resource of its own type, so one stack can declare
both.

Every store, statement and DDL comes from
[`@thomasfosterau/effect-auth/sql`](https://github.com/thomasfosterau/effect-auth/blob/trunk/docs/guides/storage.md#sql-storage-sql), the core's SQL subpath, which implements the effect-auth
storage interfaces against `SqlClient` and is shared with every other SQL
deployment. D1 is SQLite, so the same tables and the same queries apply.

## Install

```sh
pnpm add @thomasfosterau/effect-auth-alchemy-cloudflare @thomasfosterau/effect-auth effect alchemy@2.0.0-beta.85 @alchemy.run/cloudflare@2.0.0-beta.85
```

## Usage

Bind the database in your Worker with the provider's
`Cloudflare.D1.QueryDatabase`, and provide `layer(db)` to the handlers that
use effect-auth:

```ts
import * as Cloudflare from "@alchemy.run/cloudflare";
import { Effect } from "effect";
import { HttpServerRequest, HttpServerResponse } from "effect/http";
import * as Auth from "@thomasfosterau/effect-auth";
import * as AuthD1 from "@thomasfosterau/effect-auth-alchemy-cloudflare";

const AuthDatabase = Cloudflare.D1.Database("auth");

// Your auth routes, using effect-auth services over the D1 stores.
const handle = Effect.gen(function* () {
  const request = yield* HttpServerRequest.HttpServerRequest;
  const users = yield* Auth.UserStore;
  const user = yield* users.get(new URL(request.url).searchParams.get("id") ?? "");
  return HttpServerResponse.text(user === null ? "unknown" : user.id);
}).pipe(
  // A store failure is an `AuthError`; answer it rather than leak it.
  Effect.catchTag("AuthError", () =>
    Effect.succeed(HttpServerResponse.text("unavailable", { status: 503 })),
  ),
);

export default Cloudflare.Worker(
  "api",
  { main: import.meta.url },
  Effect.gen(function* () {
    // Bind the database at init; build the stores in each event.
    const db = yield* Cloudflare.D1.QueryDatabase(AuthDatabase);
    return {
      fetch: handle.pipe(Effect.provide(AuthD1.layer(db))),
    };
  }).pipe(Effect.provide(Cloudflare.D1.QueryDatabaseBinding)),
);

## Guide

The [Alchemy storage guide](https://github.com/thomasfosterau/effect-auth/blob/trunk/docs/guides/alchemy.md) covers the peers, picking single stores, transactions on D1, the `AuthSchema` action, the full API and the storage format.

## License

MIT
```
