---
"@thomasfosterau/effect-auth": minor
---

The browser client, SQL storage and SAML now ship as subpaths of the core (ADR-0022), not as packages of their own:

- `@thomasfosterau/effect-auth/client` — the typed browser client and its observable session store (formerly `@thomasfosterau/effect-auth-client`). Its in-memory server fixture is `@thomasfosterau/effect-auth/client/testing` (formerly `@thomasfosterau/effect-auth-client/testing`).
- `@thomasfosterau/effect-auth/sql` — every store it covers over `effect/sql`, the `auth_*` DDL and `migrate` (formerly `@thomasfosterau/effect-auth-sql`). It adds no dependency: `effect/sql` ships in `effect`. New: `authTableNames`, the tables the DDL creates.
- `@thomasfosterau/effect-auth/saml` — the `SamlVerifier` over `@node-saml/node-saml` (formerly `@thomasfosterau/effect-auth-saml`). `@node-saml/node-saml` (`^5.1.0`) is a new optional peer of the core, imported only by this subpath, which is Node-only.

The root barrel reaches none of the three, nor `@node-saml/node-saml`. Replace each former package import with its subpath and depend on `@thomasfosterau/effect-auth`.
