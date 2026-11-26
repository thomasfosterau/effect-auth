/**
 * `@thomasfosterau/effect-auth-alchemy-cloudflare`: effect-auth on Cloudflare
 * D1 through Alchemy. Declare {@link AuthSchema} against a
 * `Cloudflare.D1.Database` to apply the tables on deploy, and provide {@link
 * layer} with the bound D1 client at runtime. The stores are
 * `@thomasfosterau/effect-auth/sql`'s.
 */

/** The provider's D1 client → `SqlClient` → every effect-auth store. */
export * from "./Storage.ts";

/** The `AuthSchema` deploy-time action. */
export * from "./AuthSchema.ts";

/** The `SqlClient` driver over the provider's D1 client. */
export * as D1Client from "./D1Client.ts";
