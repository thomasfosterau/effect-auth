/**
 * @effect-auth/alchemy
 *
 * Everything you need to run effect-auth on Cloudflare D1 with Alchemy v2, on
 * both sides of the deploy:
 *
 * - **Provider side** — declare the {@link AuthSchema} resource in your Alchemy
 *   program and the engine keeps the auth tables reconciled on every deploy.
 * - **Consumer side** — bind the D1 database and provide {@link layer} to wire
 *   up SessionManager, EmailPasswordService, OAuth, WebAuthn and the rest.
 */

/** D1 client type and Effect query helpers. */
export * from "./D1.js";

/** SQL schema statements and the `migrate` helper. */
export * from "./Schema.js";

/** Store implementations and their layers. */
export * from "./Stores.js";

/** The structural model of Alchemy v2's resource lifecycle plus runner helpers. */
export * from "./Alchemy.js";

/** The `AuthSchema` infrastructure resource and its provider. */
export * from "./AuthSchema.js";

/** Schema table introspection and teardown helpers. */
export * from "./Tables.js";
