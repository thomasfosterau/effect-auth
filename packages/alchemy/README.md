# @thomasfosterau/effect-auth-alchemy

Cloudflare **D1** support for [`@thomasfosterau/effect-auth`](../effect-auth) on
[Alchemy v2](https://v2.alchemy.run) — the TypeScript-native, Effect-based
Infrastructure-as-Code toolkit — covering both sides of the deploy:

- **Provider side** — the [`AuthSchema`](#infrastructure-resources) resource
  provisions and keeps the auth schema reconciled in your Alchemy program.
- **Consumer side** — a D1-backed `Layer` for every effect-auth storage
  interface, so the bound database satisfies the whole auth stack.

Because both Alchemy v2 and effect-auth are built on Effect, the D1 database you
provision in your Alchemy program flows straight into an Effect `Layer` that
satisfies effect-auth's services. No ORM, no extra runtime dependencies — just
the bound D1 handle and raw SQL.

## Infrastructure resources

`AuthSchema` is an Alchemy v2 resource that keeps the effect-auth tables
(`auth_users`, `auth_sessions`, `auth_oauth_accounts`, …) reconciled inside a
Cloudflare D1 database on every deploy.

- **Idempotent** — the underlying DDL is all `CREATE TABLE IF NOT EXISTS`, so
  reconciling is cheap to repeat and additive schema changes from a library
  upgrade are picked up automatically.
- **Owns the schema, not the database** — the D1 database is passed in as a
  binding, so tearing down the stack never destroys auth data unless you opt in
  with `dropOnDelete: true`.

```ts
import { Cloudflare } from "alchemy";
import { Effect, Layer } from "effect";
import { Provider } from "alchemy/resource"; // the engine's Provider tag
import { AuthSchema, AuthSchemaProvider } from "@thomasfosterau/effect-auth-alchemy";

const AuthD1 = Cloudflare.D1Database("auth");

export default Cloudflare.Worker(
  "api",
  Effect.gen(function* () {
    const db = yield* Cloudflare.D1Database.bind(AuthD1);

    // Declare the managed schema against the bound database.
    yield* AuthSchema("auth-schema", { database: db });

    return {
      fetch: Effect.gen(function* () {
        /* ... your auth routes ... */
      }),
    };
  }),
).pipe(
  // Mount the provider so the engine can drive its lifecycle.
  Effect.provide(Layer.effect(Provider, Effect.succeed(AuthSchemaProvider))),
);
```

`AuthSchemaProvider` implements the four lifecycle hooks the Alchemy engine
expects — `read`, `diff`, `reconcile`, `delete`. They are plain Effects, so you
can also drive them directly for a one-off migration script:

```ts
import { Effect } from "effect";
import { provision, AuthSchemaProvider } from "@thomasfosterau/effect-auth-alchemy";

await Effect.runPromise(
  provision(AuthSchemaProvider, { logicalId: "auth-schema" }, { database: db }),
);
```

> `alchemy` is an **optional peer dependency**: bring it in your IaC program,
> but it is not required to build, test, or run a migration with this package.
> Like the structural `D1Database` type, the slice of Alchemy v2's resource
> lifecycle this package targets is modelled in `Alchemy.ts` rather than taken
> as a hard dependency on the `alchemy` runtime.

## Storage layers

A D1-backed `Layer` for each effect-auth `Context.Tag`:

| effect-auth service      | backing table(s)                           |
| ------------------------ | ------------------------------------------ |
| `SessionStore`           | `auth_sessions`                            |
| `UserStore`              | `auth_users`                               |
| `UserServiceStore`       | `auth_users`                               |
| `EmailPasswordStore`     | `auth_users`                               |
| `PasswordResetUserStore` | `auth_users`                               |
| `RoleStore`              | `auth_user_roles`, `auth_role_permissions` |
| `RateLimitStore`         | `auth_rate_limits`                         |
| `EmailVerificationStore` | `auth_email_verifications`                 |
| `ChallengeStore`         | `auth_webauthn_challenges`                 |
| `CredentialStore`        | `auth_webauthn_credentials`                |
| `OAuthStateStore`        | `auth_oauth_states`                        |
| `OAuthAccountStore`      | `auth_oauth_accounts`                      |
| `PasswordResetStore`     | `auth_password_resets`                     |

All tables use an `auth_` prefix so they can coexist with your application's own
schema in the same D1 database.

## Installation

```sh
bun add @thomasfosterau/effect-auth-alchemy @thomasfosterau/effect-auth effect
```

## Usage

### 1. Provision and bind D1 in your Alchemy v2 program

```ts
import { Cloudflare } from "alchemy";
import { Effect } from "effect";
import { HttpServerRequest, HttpServerResponse } from "@effect/platform";
import * as AuthDb from "@thomasfosterau/effect-auth-alchemy";
import * as Auth from "@thomasfosterau/effect-auth";

// Declare the database resource.
const AuthD1 = Cloudflare.D1Database("auth");

export default Cloudflare.Worker(
  "api",
  Effect.gen(function* () {
    // Bind the provisioned D1 database inside the worker.
    const db = yield* Cloudflare.D1Database.bind(AuthD1);

    // Create the auth schema (idempotent — safe on every cold start).
    yield* AuthDb.migrate(db);

    return {
      fetch: Effect.gen(function* () {
        const request = yield* HttpServerRequest.HttpServerRequest;
        // ... your auth routes, using effect-auth services ...
        return HttpServerResponse.text("ok");
      }).pipe(
        // Provide persistence for the whole effect-auth stack.
        Effect.provide(AuthDb.layer(db)),
      ),
    };
  }),
);
```

> The only thing this package needs from Alchemy is the bound D1 handle. The
> handle returned by `Cloudflare.D1Database.bind(...)` satisfies the small
> structural `D1Database` type exported here, as do the `D1Database` type from
> `@cloudflare/workers-types` and Miniflare's local implementation.

### 2. Wire effect-auth services on top

`AuthDb.layer(db)` provides every store tag, so higher-level effect-auth layers
compose directly:

```ts
import { Effect, Layer } from "effect";
import * as Auth from "@thomasfosterau/effect-auth";
import * as AuthDb from "@thomasfosterau/effect-auth-alchemy";

const SessionConfig = {
  sessionExpiresIn: { activePeriod: 30 * 24 * 60 * 60 * 1000, idlePeriod: 7 * 24 * 60 * 60 * 1000 },
};

const AppLayer = (db: AuthDb.D1Database) =>
  Auth.SessionManagerLayer(SessionConfig).pipe(Layer.provideMerge(AuthDb.layer(db)));

const login = (db: AuthDb.D1Database, userId: string) =>
  Effect.gen(function* () {
    const sessions = yield* Auth.SessionManager;
    return yield* sessions.createSession(userId);
  }).pipe(Effect.provide(AppLayer(db)));
```

### Individual layers

If you only need a subset of stores, use the per-store layer factories instead
of `layer(db)`:

```ts
Layer.mergeAll(AuthDb.SessionStoreLayer(db), AuthDb.UserStoreLayer(db));
```

## Schema & migrations

`migrate(db)` runs the DDL in `schemaStatements` (all `CREATE ... IF NOT
EXISTS`). You can also run the statements yourself — for example through
Alchemy/Wrangler migrations — by importing `schemaStatements`.

```ts
import { schemaStatements } from "@thomasfosterau/effect-auth-alchemy";
```

## Notes

- **Timestamps** are stored as epoch milliseconds (`INTEGER`).
- **`attributes`** and **`transports`** are stored as JSON `TEXT`.
- **Binary values** (WebAuthn challenges and public keys) are stored
  base64-encoded.
- Methods whose error channel is `never` (e.g. `RoleStore`, `RateLimitStore.get`)
  treat a database failure as a defect, so authorization fails closed rather
  than silently granting access.
- effect-auth uses `node:crypto`, so run your Worker with the `nodejs_compat`
  flag.
