/**
 * @effect-auth/alchemy-resources
 *
 * Alchemy v2 resources that provision and manage the infrastructure
 * effect-auth needs. The headline resource is {@link AuthSchema}: a managed
 * Cloudflare D1 schema migration that keeps the effect-auth tables reconciled
 * on every deploy.
 *
 * This is the provider-side companion to `@effect-auth/alchemy`, which provides
 * the consumer-side storage `Layer`s. Provision your infrastructure here, then
 * bind the database and wire the stores there.
 */

/** The structural model of Alchemy v2's resource lifecycle plus runner helpers. */
export * from "./Alchemy.js";

/** The `AuthSchema` resource and its provider. */
export * from "./AuthSchema.js";

/** Schema table introspection and teardown helpers. */
export * from "./Tables.js";
