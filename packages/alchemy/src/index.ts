/**
 * `@thomasfosterau/effect-auth-alchemy` — run effect-auth on Cloudflare D1,
 * on both sides of the deploy:
 *
 * - **Provider side** — declare the {@link AuthSchema} resource in your
 *   Alchemy program and the engine keeps the auth tables reconciled on every
 *   deploy.
 * - **Consumer side** — provide {@link layer} with your D1 binding and the
 *   whole auth stack (SessionService, EmailPasswordService, OAuth, WebAuthn,
 *   ...) has persistence.
 *
 * The queries are not this package's: every store comes from
 * `@thomasfosterau/effect-auth-sql`, written against `effect/unstable/sql`'s
 * `SqlClient`. All this package adds is the D1 driver for that client
 * ({@link D1Client}) and the Alchemy resource.
 */

/** D1 binding → `SqlClient` → every effect-auth store. */
export * from "./Storage.ts";

/** The `AuthSchema` infrastructure resource and its provider. */
export * from "./AuthSchema.ts";

/** The `SqlClient` driver for a Cloudflare D1 binding. */
export * as D1Client from "./D1Client.ts";
