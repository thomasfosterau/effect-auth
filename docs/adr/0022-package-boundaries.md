# Package boundaries: merge into core unless a package brings a dependency

effect-auth grew one package per tier or adapter: a browser client (`effect-auth-client`), SQL
storage (`effect-auth-sql`), a SAML verifier (`effect-auth-saml`) and one Alchemy package covering
both Cloudflare D1 and Postgres (`effect-auth-alchemy`). None of them was ever published. Several
carried nothing the core lacked:

- The client imports the core's HTTP tier for types only and runs on plain `fetch`.
- The SQL stores are written against `effect/sql`, which ships in `effect` itself.
- The SAML verifier's one dependency, `@node-saml/node-saml`, can be an optional peer reached from
  one subpath, the way `@thomasfosterau/effect-jsonapi` already is for `./http`.

Each package added a manifest, a build, a `check:dist` target, a fallow zone, a README and a
release to coordinate. It also put a version boundary between code that always moves together:
every change to a store contract landed in the core and in `effect-auth-sql` at once.

The Alchemy package had the opposite problem. Its D1 half and its Postgres half need different
Alchemy providers (`@alchemy.run/cloudflare` for one, nothing provider-specific for the other) and
different drivers. A consumer of one half installed the other half's peers, or met them as optional
peers that nothing could check.

## Decision

The owner's rules (2026-11-06):

1. **Merge into core unless the package brings a dependency the core lacks.** A module that needs
   only `effect`, or a dependency the core already has, is a core subpath. A third-party library
   that only one subpath needs becomes an optional peer of the core, reached from that subpath only
   and pinned by `ModuleGraph.test.ts` as unreachable from the root. The owner's own libraries
   (effect-jsonapi, effect-connect, …) count as dependencies. Runtime platforms do not: Node-only
   or browser-only code is not a reason for a package of its own, and a subpath says in its README
   and doc comments which runtime it needs.
2. **Alchemy packages are split per Alchemy provider.** Each one peers on `alchemy` and on its
   provider's `@alchemy.run/*` package at the exact release the applications pin. Code that no
   provider gives anything to depend on stays one package, named for what it is.
3. **Vendor adapters are merged case by case**, by the owner.

Applied:

- `effect-auth-client` → `@thomasfosterau/effect-auth/client`; its `./testing` fixture →
  `/client/testing`, because the core already has `./testing`.
- `effect-auth-sql` → `@thomasfosterau/effect-auth/sql`.
- `effect-auth-saml` → `@thomasfosterau/effect-auth/saml`, with `@node-saml/node-saml` as an
  optional peer of the core. It stays Node-only.
- `effect-auth-alchemy` → `@thomasfosterau/effect-auth-alchemy-cloudflare` (D1: `D1Client`, the
  storage wiring and a D1 `AuthSchema`; peers `alchemy` and `@alchemy.run/cloudflare`) and
  `@thomasfosterau/effect-auth-alchemy-postgres` (Postgres over Hyperdrive or a URL and a Postgres
  `AuthSchema`; peers `alchemy` and `@effect/sql-pg`). The Postgres half was to be
  `effect-auth-alchemy-planetscale`, peering on `@alchemy.run/planetscale`, but the code is
  host-agnostic Postgres. The provider layer is built before any resource exists, so a
  `PostgresRole`'s outputs never reach it. The role's `connectionUrl` is already a
  `Redacted<string>` that `database(url)` takes unchanged. Rule 2's fallback names the package for
  what it is. The two `AuthSchema` resources have distinct types (`effect-auth::D1AuthSchema`,
  `effect-auth::PostgresAuthSchema`), so one stack can mount both providers.
  [ADR-0023](0023-alchemy-packages-on-provider-services.md) later rebuilt the D1 package on
  `@alchemy.run/cloudflare`'s services: its D1 `AuthSchema` is now an Alchemy Action.
- `effect-auth-argon2` (`hash-wasm`), `effect-auth-drizzle` (`drizzle-orm`) and the Svelte binding
  (`svelte`) bring dependencies and stay packages. `effect-auth-resend`, `effect-auth-twilio` and
  `effect-auth-sveltekit` stay as they are, by the owner's decision.

## Consequences

- The core's fallow zone covers the merged code. The zones that said "client imports only core"
  and "bindings import only client" are gone: the Svelte and SvelteKit bindings may import the
  core, including `/client`.
- `ModuleGraph.test.ts` keeps the root barrel free of the HTTP tier, of the `client/`, `sql/` and
  `saml/` directories, and of `@node-saml/node-saml`. `/client` may reach the HTTP tier.
- The core's `tsconfig.json` adds the `DOM` lib for `client/`. The rest of the core still runs on
  Workers and Node.
- A new package now needs a reason under rule 1 or 2. Without one, it is a subpath.
