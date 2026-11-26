# effect-auth

Authentication and authorization for [Effect](https://effect.website/) v4: a headless core of services and layers (sessions, passwords, passkeys, multi-factor, OAuth, SSO, organizations, API keys, JWT, one policy-based authorization kernel), with an optional HTTP API, browser client, Svelte bindings and storage and vendor adapters. Email and SMS go through [effect-connect](https://github.com/thomasfosterau/effect-connect)'s providers.

> [!WARNING]
> Experimental, pre-1.0 and largely written with Claude Code. It is **not production-ready**, has not been audited, and its API will change. For something usable today, use [Better Auth](https://www.better-auth.com/).

## Install

```sh
pnpm add @thomasfosterau/effect-auth effect
```

## Usage

```ts
import { Effect } from "effect";
import * as Auth from "@thomasfosterau/effect-auth";

const signIn = Effect.gen(function* () {
  const auth = yield* Auth.Email.EmailPasswordService;
  return yield* auth.signIn({ email: "ada@example.com", password: "correct horse battery staple" });
});
```

Provide `EmailPasswordService.layer()` with its stores (in memory, `/sql` or an adapter); the [getting-started guide](docs/guides/getting-started.md) has the full, runnable setup.

## Packages

| Package                                                         | Purpose                                                         |
| --------------------------------------------------------------- | --------------------------------------------------------------- |
| [`effect-auth`](packages/effect-auth)                           | The core; subpaths `/http`, `/client`, `/sql`, `/saml` and more |
| [`effect-auth-svelte`](packages/svelte)                         | Svelte bindings over `/client`                                  |
| [`effect-auth-sveltekit`](packages/sveltekit)                   | SvelteKit `handle` hook and form actions                        |
| [`effect-auth-drizzle`](packages/drizzle)                       | Drizzle stores for PostgreSQL, SQLite and MySQL                 |
| [`effect-auth-alchemy-cloudflare`](packages/alchemy-cloudflare) | Alchemy schema resource and D1 stores                           |
| [`effect-auth-alchemy-postgres`](packages/alchemy-postgres)     | Alchemy schema resource and Postgres stores                     |
| [`effect-auth-argon2`](packages/argon2)                         | Argon2id over WebAssembly, for Workers                          |
| [`effect-auth-better-auth`](packages/better-auth)               | BetterAuth as the backend for the core services (private)       |

All are published under `@thomasfosterau/`, except `effect-auth-better-auth`, which is not published yet.

## Links

- [Architecture](docs/ARCHITECTURE.md), [design](docs/DESIGN.md), [decisions](docs/adr/README.md), [glossary](docs/CONTEXT.md) and [guides](docs/guides/)
- [Contributing](docs/CONTRIBUTING.md) · [Security](docs/SECURITY.md) · [Publishing](docs/PUBLISHING.md)
- [MIT licence](LICENSE.md)
