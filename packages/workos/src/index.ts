/**
 * @effect-auth/workos
 *
 * Effect-native bindings for the [WorkOS](https://workos.com) Node SDK that make
 * the entire WorkOS feature set available as typed Effects: SSO, AuthKit / User
 * Management, Directory Sync (SCIM), Organizations, Multi-Factor Auth, Audit
 * Logs, Events, Webhooks, Fine-Grained Authorization, Vault, Widgets, the Admin
 * Portal, Passwordless / Magic Auth and more.
 *
 * Provide a {@link WorkOS} layer and access every module as Effects:
 *
 * @example
 * import { Effect } from "effect"
 * import { WorkOS } from "@effect-auth/workos"
 *
 * const authenticate = (email: string, password: string) =>
 *   Effect.gen(function* () {
 *     const workos = yield* WorkOS
 *     return yield* workos.userManagement.authenticateWithPassword({
 *       clientId: process.env.WORKOS_CLIENT_ID!,
 *       email,
 *       password,
 *     })
 *   })
 *
 * authenticate("user@example.com", "secret").pipe(Effect.provide(WorkOS.layer))
 */

/** The WorkOS service, its layers, client construction and the effectify types. */
export * from "./WorkOS.js";

/** The {@link WorkOSError} tagged error and helpers for mapping SDK exceptions. */
export * from "./Errors.js";

/**
 * Re-export of the WorkOS Node SDK's types and value exports (event payloads,
 * option/response interfaces, exception classes, enums, ...) so consumers can
 * import everything from a single entry point.
 */
export * as WorkOSSDK from "@workos-inc/node";
