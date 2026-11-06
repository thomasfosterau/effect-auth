/**
 * `@thomasfosterau/effect-auth-alchemy-postgres` — run effect-auth on Postgres
 * from an Alchemy stack, on both sides of the deploy:
 *
 * - **Provider side** — mount {@link AuthSchemaProvider} with a
 *   {@link database} (reached by URL), declare the {@link AuthSchema} resource
 *   in your Alchemy program, and the engine keeps the auth tables reconciled
 *   on every deploy.
 * - **Consumer side** — provide {@link layer} with a Cloudflare Hyperdrive
 *   binding (or a Postgres URL) and the whole auth stack has persistence.
 *
 * The queries are not this package's: every store comes from
 * `@thomasfosterau/effect-auth/sql`, written against `effect/sql`'s
 * `SqlClient`. This package adds the `@effect/sql-pg` client wiring and the
 * Alchemy resource. It is named for the database, not an Alchemy provider:
 * nothing here depends on how the Postgres server is hosted (ADR-0022).
 */

/** Hyperdrive binding or URL → `SqlClient` → every effect-auth store. */
export * from "./Postgres.ts";

/** The `AuthSchema` infrastructure resource and its provider. */
export * from "./AuthSchema.ts";
