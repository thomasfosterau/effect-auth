/**
 * `@thomasfosterau/effect-auth-sveltekit` (ADR-0021): {@link handle} resolves
 * the session before `load` and keeps signed-in pages out of shared caches;
 * {@link credentialAction}, {@link credentialForm} and {@link
 * credentialCommand} run the credential flows. It is typed against SvelteKit's
 * `RequestEvent`, with no dependency on `@sveltejs/kit`.
 *
 * @module
 */

export * from "./Handle.ts";
export * from "./Actions.ts";
