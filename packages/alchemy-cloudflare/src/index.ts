/**
 * `@thomasfosterau/effect-auth-alchemy-cloudflare`: effect-auth on Cloudflare
 * D1 through Alchemy. Declare {@link AuthSchema.AuthSchema} against a
 * `Cloudflare.D1.Database` to apply the tables on deploy, and provide {@link
 * Storage.layer} with the bound D1 client at runtime. The stores are
 * `@thomasfosterau/effect-auth/sql`'s.
 */

export * as AuthSchema from "./AuthSchema.ts";
/** The `SqlClient` driver over the provider's D1 client. */
export * as D1Client from "./D1Client.ts";
export * as Storage from "./Storage.ts";
