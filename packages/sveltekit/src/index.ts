/**
 * `@thomasfosterau/effect-auth-sveltekit` (ADR-0021): {@link Handle.handle} resolves
 * the session before `load` and keeps signed-in pages out of shared caches;
 * {@link Actions.credentialAction}, {@link Actions.credentialForm} and {@link
 * Actions.credentialCommand} run the credential flows. It is typed against SvelteKit's
 * `RequestEvent`, with no dependency on `@sveltejs/kit`.
 *
 * @module
 */

export * as Actions from "./Actions.ts";
export * as Handle from "./Handle.ts";
