/**
 * `@thomasfosterau/effect-auth-alchemy-postgres`: effect-auth on Postgres from
 * an Alchemy stack. Mount {@link AuthSchema.AuthSchemaProvider} with a {@link Postgres.database}
 * and declare {@link AuthSchema.AuthSchema} to reconcile the tables on deploy; provide
 * {@link Postgres.layer} with a Hyperdrive binding or URL at runtime. The stores are
 * `@thomasfosterau/effect-auth/sql`'s.
 */

export * as AuthSchema from "./AuthSchema.ts";
export * as Postgres from "./Postgres.ts";
