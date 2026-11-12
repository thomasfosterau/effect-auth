# @thomasfosterau/effect-auth-alchemy-cloudflare

Cloudflare **D1** support for [`@thomasfosterau/effect-auth`](https://github.com/thomasfosterau/effect-auth/tree/trunk/packages/effect-auth) on
[Alchemy v2](https://v2.alchemy.run) — the TypeScript-native, Effect-based
Infrastructure-as-Code toolkit — covering both sides of the deploy:

- **Deploy side** — the [`AuthSchema`](#the-authschema-action) action, so the
  Alchemy engine applies the auth schema to your `Cloudflare.D1.Database` on
  deploy.
- **Runtime side** — [`layer(db)`](#storage-layers), which turns the client
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
[`@thomasfosterau/effect-auth/sql`](https://github.com/thomasfosterau/effect-auth/tree/trunk/packages/effect-auth#sql-storage-sql), the core's SQL subpath, which implements the effect-auth
storage interfaces against `SqlClient` and is shared with every other SQL
deployment. D1 is SQLite, so the same tables and the same queries apply.

## Install

```sh
pnpm add @thomasfosterau/effect-auth-alchemy-cloudflare @thomasfosterau/effect-auth effect alchemy@2.0.0-beta.85 @alchemy.run/cloudflare@2.0.0-beta.85
```

`alchemy` and `@alchemy.run/cloudflare` (both exactly `2.0.0-beta.85`, the
release the effect-auth applications pin) and `effect` (`^4.1.0`) are required
peer dependencies. Every `@alchemy.run/*` provider peers on `alchemy` at its
own exact version, and beta.85 is the first alchemy on Effect 4.1's
`effect/crypto` modules (beta.84 and earlier import `effect/Crypto`, which 4.1
removed); it peers on `effect ^4.1.0` itself. `@thomasfosterau/effect-auth`
comes along as a dependency, for its `/sql` subpath.

## Storage layers

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
```

`AuthD1.layer(db)` provides every store `@thomasfosterau/effect-auth/sql`
implements — `SessionStore`, `UserStore`, `EmailPasswordStore`,
`RateLimitStore`, `EmailVerificationStore`, `ChallengeStore`, `CredentialStore`,
`OAuthStateStore`, `OAuthAccountStore`, `PasswordResetStore`, `MagicLinkStore`,
`EmailOtpStore`, `MultiFactorStore`, `IdentifierStore`, … — all backed by
`auth_`-prefixed tables so they coexist with your application's own schema.
The provider's statements run inside an Alchemy event (they need its
`RuntimeContext`), so the layer is built where the handler runs, and captures
that context for every statement.

For a subset, provide `D1Client.layer({ db })` and pick the per-store layers
from `@thomasfosterau/effect-auth/sql` directly:

```ts
import type { QueryDatabaseClient } from "@alchemy.run/cloudflare/D1";
import { Layer } from "effect";
import * as Sql from "@thomasfosterau/effect-auth/sql";
import { D1Client } from "@thomasfosterau/effect-auth-alchemy-cloudflare";

export const SessionStores = (db: QueryDatabaseClient) =>
  Layer.mergeAll(Sql.SessionStoreLayer, Sql.UserStoreLayer).pipe(
    Layer.provide(D1Client.layer({ db })),
  );
```

`@alchemy.run/cloudflare`'s own `D1/SQL` module is not used: it wraps
`@effect/sql-d1`, whose client dies on a transaction (see below), and several
store methods ask for one.

### Transactions

D1 has no interactive transactions — `BEGIN` / `COMMIT` / `SAVEPOINT` are
rejected, and `batch()` (statements run in order and rolled back together on
failure) is its only atomic primitive. `D1Client` maps a transaction onto it:
a write that returns no rows is buffered, a statement that returns rows (a
`SELECT`, or a write with `RETURNING`) is sent in one batch with the writes
buffered before it, and `COMMIT` sends the rest as one batch. So:

- `ChallengeStore.create` (two `DELETE`s, then the challenge's and its
  ceremony's `INSERT`s), `OAuthStateStore.create` and `EmailOtpStore.upsert`
  (each a `DELETE` followed by an `INSERT`), and `ChallengeStore.delete` and
  `PendingMultiFactorStore.delete` (two `DELETE`s each) are **atomic** on D1:
  one batch each.
- `IdentifierStore.replace`, which email change uses, sends its claim of the
  new address and its release of the old one (a `DELETE … RETURNING` guarded on
  the old address) in one batch, so they commit together. Of two concurrent
  replaces of the same address one succeeds; the other finds nothing to
  release and deletes its own claim again, in a batch of its own, so a failure
  before that batch leaves the user holding both new addresses.
- In general, what was sent before a read stays committed if a later batch
  fails or the effect rolls back, and D1 isolates nothing between batches.
  Everything else that needs atomicity is already a single statement
  (`ON CONFLICT … DO UPDATE`, `UPDATE … RETURNING`).

## The `AuthSchema` action

`AuthSchema(id, database)` applies the effect-auth tables (`auth_users`,
`auth_sessions`, `auth_oauth_accounts`, …) to a `Cloudflare.D1.Database` on
deploy. It is an Alchemy `Action`, built the way `@alchemy.run/cloudflare`
documents deploy-time database work: its init binds the database with
`Cloudflare.D1.QueryDatabase`, its body runs `@thomasfosterau/effect-auth/sql`'s
DDL through that client, and the application provides
`Cloudflare.D1.QueryDatabaseLocal` — the provider's deploy-time client, over
the Cloudflare HTTP API with the stack's credentials, or the local simulator
under `alchemy dev`:

```ts
import * as Alchemy from "alchemy";
import * as Cloudflare from "@alchemy.run/cloudflare";
import { Effect } from "effect";
import { AuthSchema } from "@thomasfosterau/effect-auth-alchemy-cloudflare";

export default Alchemy.Stack(
  "api",
  { providers: Cloudflare.providers(), state: Cloudflare.state() },
  Effect.gen(function* () {
    const db = yield* Cloudflare.D1.Database("auth");
    yield* AuthSchema("auth-schema", db).pipe(Effect.provide(Cloudflare.D1.QueryDatabaseLocal));
    // … the Worker that binds `db`
  }),
);
```

- **In dependency order** — the engine runs it after the database exists, in
  the same deploy.
- **When its input changes** — the database id and the DDL. A replaced
  database or a library upgrade that adds a table re-runs it; an unchanged one
  is skipped (`alchemy deploy --force` re-runs it). The DDL is all
  `CREATE … IF NOT EXISTS`, so a re-run is harmless.
- **No delete** — an Action has none: removing or destroying `AuthSchema` leaves
  the tables. They go with the `Cloudflare.D1.Database` when it is destroyed.
- **One per database** — each call declares its own Action, so a stack can
  apply the schema to several databases under distinct ids. Its type,
  `effect-auth::D1AuthSchema`, differs from the Postgres package's resource.

`Cloudflare.D1.Database`'s own `migrations` is not used for this: it reads one
directory of `.sql` files, which your application's migrations occupy, and the
auth DDL is code, shared with every other SQL deployment.

Outside an Alchemy deploy — a cold start, a script — call `migrate(db)` with a
bound client instead.

> `alchemy` and `@alchemy.run/cloudflare` are **required peer dependencies**.
> The action, the D1 client and their types all come from them; there is no
> vendored or structural copy here.

## API

- `layer(db): Layer<AuthStores, never, RuntimeContext>` — every `@thomasfosterau/effect-auth/sql` store over the client `Cloudflare.D1.QueryDatabase(database)` binds (`AuthStores` is that store set).
- `migrate(db): Effect<void, AuthError, RuntimeContext>` — the `/sql` DDL through that client.
- `purgeExpired(db): Effect<PurgeExpiredResult, AuthError, RuntimeContext>` — `/sql`'s `purgeExpired` through that client: deletes the expired magic-link and email-OTP rows and the rate-limit rows whose window and block have both passed. Nothing else deletes them, so call it from a cron trigger's `scheduled` handler.
- `AuthSchema(id, database)` — the Alchemy Action (input `AuthSchemaInput`, output `AuthSchemaAttributes`), type `AUTH_SCHEMA_TYPE` (`effect-auth::D1AuthSchema`). It needs a `Cloudflare.D1.QueryDatabase` (`Cloudflare.D1.QueryDatabaseLocal` on deploy).
- `authTableNames` — the tables the schema owns, derived from `/sql`'s DDL (`Sql.authTableNames`).
- `D1Client` — `make({ db })` / `layer({ db })`: a `SqlClient` over a `QueryDatabaseClient`, needing the event's `RuntimeContext`.

## Notes

- **Timestamps** are stored as epoch milliseconds in `BIGINT` columns (SQLite
  treats these as 64-bit `INTEGER`), so dates past 2038 survive the round trip
  on D1.
- **`attributes`** and **`transports`** are JSON `TEXT`; **binary values**
  (WebAuthn challenges and public keys) are base64 `TEXT`.
- Token columns store the SHA-256 hash computed by the service layer — the
  database never sees a raw bearer token.
- effect-auth uses `node:crypto`, so run your Worker with the `nodejs_compat`
  flag.

## License

MIT
