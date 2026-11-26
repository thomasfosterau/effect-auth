/**
 * `@thomasfosterau/effect-auth-alchemy-postgres`: effect-auth on Postgres from
 * an Alchemy stack. Mount {@link AuthSchemaProvider} with a {@link database}
 * and declare {@link AuthSchema} to reconcile the tables on deploy; provide
 * {@link layer} with a Hyperdrive binding or URL at runtime. The stores are
 * `@thomasfosterau/effect-auth/sql`'s.
 */

/** Hyperdrive binding or URL → `SqlClient` → every effect-auth store. */
export * from "./Postgres.ts";

/** The `AuthSchema` infrastructure resource and its provider. */
export * from "./AuthSchema.ts";
