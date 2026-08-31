/**
 * @thomasfosterau/effect-auth-alchemy
 *
 * Everything you need to run effect-auth on Cloudflare D1 with Alchemy v2, on
 * both sides of the deploy:
 *
 * - **Provider side** — declare the {@link AuthSchema} resource in your Alchemy
 *   program and the engine keeps the auth tables reconciled on every deploy.
 * - **Consumer side** — bind the D1 database and provide {@link layer} to wire
 *   up SessionService, EmailPasswordService, OAuth, WebAuthn and the rest.
 */

/** D1 client type and Effect query helpers. */
export * from "./D1.ts";

/** SQL schema statements and the `migrate` helper. */
export * from "./Schema.ts";

/** Store implementations and their layers. */
export * from "./Stores.ts";

/** Helpers for driving a real Alchemy v2 provider outside the engine. */
export * from "./Alchemy.ts";

/** The `AuthSchema` infrastructure resource and its provider. */
export * from "./AuthSchema.ts";

/** Schema table introspection and teardown helpers. */
export * from "./Tables.ts";
