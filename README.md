# effect-auth

Authentication and authorization for [Effect](https://effect.website/) v4: a headless core of services and layers, plus an optional HTTP API, a typed browser client, framework bindings and storage and vendor adapters, each opt-in. How it relates to effect-jsonapi and legation is stated once in [the three-library boundary](docs/BOUNDARY.md).

## Packages

| Package                                                   | Purpose                                                                                                         |
| --------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------- |
| [`@thomasfosterau/effect-auth`](packages/effect-auth)     | The core library; `effect` is its only dependency. Start with its [README](packages/effect-auth/README.md).     |
| [`@thomasfosterau/effect-auth-client`](packages/client)   | Typed browser client over the HTTP contract, with an observable session store                                   |
| [`@thomasfosterau/effect-auth-react`](packages/react)     | React hooks and form components over the client                                                                 |
| [`@thomasfosterau/effect-auth-svelte`](packages/svelte)   | Svelte bindings and form components over the client                                                             |
| [`@thomasfosterau/effect-auth-vue`](packages/vue)         | Vue composables and form components over the client                                                             |
| [`@thomasfosterau/effect-auth-solid`](packages/solid)     | Solid primitives and form components over the client                                                            |
| [`@thomasfosterau/effect-auth-sql`](packages/sql)         | Driver-agnostic SQL storage layers (`effect/sql`)                                                               |
| [`@thomasfosterau/effect-auth-drizzle`](packages/drizzle) | Drizzle storage layers for PostgreSQL, SQLite and MySQL                                                         |
| [`@thomasfosterau/effect-auth-alchemy`](packages/alchemy) | Alchemy v2 `AuthSchema` resource and D1 storage layers (held private until alchemy ships an rc.118 build, #250) |
| [`@thomasfosterau/effect-auth-argon2`](packages/argon2)   | Argon2id `PasswordHasher` on WebAssembly (`hash-wasm`), Workers-safe                                            |
| [`@thomasfosterau/effect-auth-resend`](packages/resend)   | Resend `EmailSender` over plain `fetch`                                                                         |
| [`@thomasfosterau/effect-auth-twilio`](packages/twilio)   | Twilio `SmsSender` over plain `fetch`                                                                           |
| [`@thomasfosterau/effect-auth-saml`](packages/saml)       | SAML 2.0 `SamlVerifier` over `@node-saml/node-saml`                                                             |

## Documentation

- [Architecture](docs/ARCHITECTURE.md) (module map and security model), [design decisions](docs/DESIGN.md), [ADRs](docs/adr/README.md) and the [domain vocabulary](docs/CONTEXT.md).
- Guides in [docs/guides/](docs/guides/): bring your own store, the browser client, MCP provider, SCIM, auth as a separate service, migrating from Better Auth, migrating to the authorization kernel.

## Development

See [CONTRIBUTING.md](CONTRIBUTING.md). Report vulnerabilities as described in [SECURITY.md](SECURITY.md).

## License

MIT — see [LICENSE.md](LICENSE.md).
