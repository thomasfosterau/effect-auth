/**
 * `@thomasfosterau/effect-auth-alchemy-cloudflare` — run effect-auth on
 * Cloudflare D1, built on Alchemy's Cloudflare provider
 * (`@alchemy.run/cloudflare`), on both sides of the deploy:
 *
 * - **Deploy side** — declare the {@link AuthSchema} action against your
 *   `Cloudflare.D1.Database` in your Alchemy program, and the engine applies
 *   the auth tables on deploy.
 * - **Runtime side** — provide {@link layer} with the client
 *   `Cloudflare.D1.QueryDatabase(database)` binds, and the whole auth stack
 *   (SessionService, EmailPasswordService, OAuth, WebAuthn, ...) has
 *   persistence.
 *
 * The queries are not this package's: every store comes from
 * `@thomasfosterau/effect-auth/sql`, written against `effect/sql`'s
 * `SqlClient`. All this package adds is a `SqlClient` over the provider's D1
 * client ({@link D1Client}) and the Alchemy action. Postgres (over Hyperdrive
 * or a URL) is the separate `@thomasfosterau/effect-auth-alchemy-postgres`
 * package, so a D1 app never loads `@effect/sql-pg`.
 */

/** The provider's D1 client → `SqlClient` → every effect-auth store. */
export * from "./Storage.ts";

/** The `AuthSchema` deploy-time action. */
export * from "./AuthSchema.ts";

/** The `SqlClient` driver over the provider's D1 client. */
export * as D1Client from "./D1Client.ts";
