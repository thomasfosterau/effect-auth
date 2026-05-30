# @effect-auth/alchemy

Cloudflare **D1**-backed implementations of every [`effect-auth`](../effect-auth)
storage interface, designed to be provisioned and bound with
[Alchemy v2](https://v2.alchemy.run) — the TypeScript-native, Effect-based
Infrastructure-as-Code toolkit.

Because both Alchemy v2 and effect-auth are built on Effect, the D1 database you
provision in your Alchemy program flows straight into an Effect `Layer` that
satisfies effect-auth's services. No ORM, no extra runtime dependencies — just
the bound D1 handle and raw SQL.

## What you get

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
bun add @effect-auth/alchemy effect-auth effect
```

## Usage

### 1. Provision and bind D1 in your Alchemy v2 program

```ts
import { Cloudflare } from "alchemy";
import { Effect } from "effect";
import { HttpServerRequest, HttpServerResponse } from "@effect/platform";
import * as AuthDb from "@effect-auth/alchemy";
import * as Auth from "effect-auth";

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
import * as Auth from "effect-auth";
import * as AuthDb from "@effect-auth/alchemy";

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
import { schemaStatements } from "@effect-auth/alchemy";
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
