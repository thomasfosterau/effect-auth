# @effect-auth/alchemy-resources

[Alchemy v2](https://v2.alchemy.run) resources that **provision and manage the
infrastructure** [`effect-auth`](../effect-auth) needs. This is the
provider-side companion to [`@effect-auth/alchemy`](../alchemy), which provides
the consumer-side storage `Layer`s:

| Package                          | Side     | Responsibility                                                  |
| -------------------------------- | -------- | --------------------------------------------------------------- |
| `@effect-auth/alchemy-resources` | provider | Declare & reconcile the auth infrastructure (the D1 **schema**) |
| `@effect-auth/alchemy`           | consumer | Turn a bound D1 handle into effect-auth's storage `Layer`s      |

Both Alchemy v2 and effect-auth are built on Effect, so the database you
provision flows straight through to the `Layer` that satisfies effect-auth's
services.

## The `AuthSchema` resource

`AuthSchema` is an Alchemy v2 resource that keeps the effect-auth tables
(`auth_users`, `auth_sessions`, `auth_oauth_accounts`, …) reconciled inside a
Cloudflare D1 database on every deploy.

- **Idempotent** — the underlying DDL is all `CREATE TABLE IF NOT EXISTS`, so
  reconciling is cheap to repeat and additive schema changes from a library
  upgrade are picked up automatically.
- **Owns the schema, not the database** — the D1 database is passed in as a
  binding, so tearing down the stack never destroys auth data unless you opt in
  with `dropOnDelete: true`.

The table list is derived from `@effect-auth/alchemy`'s `schemaStatements`, so
the two packages can never drift.

## Installation

```sh
bun add @effect-auth/alchemy-resources @effect-auth/alchemy effect-auth effect
# alchemy itself is an optional peer — add it for your IaC program:
bun add -D alchemy
```

## Usage

### Provision the schema in your Alchemy v2 program

```ts
import { Cloudflare } from "alchemy";
import { Effect, Layer } from "effect";
import { Provider } from "alchemy/resource"; // the engine's Provider tag
import { AuthSchema, AuthSchemaProvider } from "@effect-auth/alchemy-resources";

// 1. Provision a D1 database.
const AuthD1 = Cloudflare.D1Database("auth");

export default Cloudflare.Worker(
  "api",
  Effect.gen(function* () {
    const db = yield* Cloudflare.D1Database.bind(AuthD1);

    // 2. Declare the managed schema against the bound database.
    yield* AuthSchema("auth-schema", { database: db });

    return {
      fetch: Effect.gen(function* () {
        // ... your auth routes ...
      }),
    };
  }),
).pipe(
  // 3. Mount the provider so the engine can drive its lifecycle.
  Effect.provide(Layer.effect(Provider, Effect.succeed(AuthSchemaProvider))),
);
```

> The exact wiring of a custom provider into the engine follows Alchemy v2's
> [custom resource provider guide](https://v2.alchemy.run/concepts/resource/).
> `AuthSchemaProvider` implements the four lifecycle hooks (`read`, `diff`,
> `reconcile`, `delete`) the engine expects.

### Run a migration without the engine

`AuthSchemaProvider`'s hooks are plain Effects, so you can also drive them
directly — useful for a one-off migration script or in tests:

```ts
import { Effect } from "effect";
import { provision, AuthSchemaProvider } from "@effect-auth/alchemy-resources";

await Effect.runPromise(
  provision(AuthSchemaProvider, { logicalId: "auth-schema" }, { database: db }),
);
```

### Wire effect-auth on top

Once the schema exists, hand the same bound handle to `@effect-auth/alchemy`:

```ts
import { layer } from "@effect-auth/alchemy";
import * as Auth from "effect-auth";

const AppLayer = Auth.SessionManagerLayer(sessionConfig).pipe(Layer.provideMerge(layer(db)));
```

## API

- **`AuthSchema`** — the declared resource (`type: "effect-auth::AuthSchema"`).
- **`AuthSchemaProvider`** — the lifecycle provider (`read` / `diff` /
  `reconcile` / `delete`).
- **`AuthSchemaProps`** — `{ database, dropOnDelete? }`.
- **`AuthSchemaAttributes`** — `{ tables, statements, appliedAt }`.
- **`authTableNames`** — every table the schema manages.
- **`listAuthTables(db)`** / **`dropAuthTables(db)`** — introspection & teardown.
- **`provision` / `deprovision`** — run a provider's lifecycle outside the
  Alchemy engine.

## Design note

Like the sibling `@effect-auth/alchemy` package — which models the D1 client
with a small structural interface instead of depending on
`@cloudflare/workers-types` — this package models the slice of Alchemy v2's
resource lifecycle it targets (see `Alchemy.ts`) rather than taking a hard
dependency on the `alchemy` runtime. `alchemy` is therefore an **optional peer
dependency**: bring it in your IaC program, but it is not required to build,
test, or run a migration with this package.
