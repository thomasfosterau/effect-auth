/**
 * `@thomasfosterau/effect-auth-sveltekit`: the server side of effect-auth in
 * a SvelteKit app (ADR-0021).
 *
 * - {@link handle}: the `handle` hook. It resolves the session before `load`,
 *   with the core's cookieless skip and an explicit fail-open or fail-closed
 *   choice, and forces `private, no-store` on pages rendered for a signed-in
 *   viewer.
 * - {@link credentialAction}: the form action for a credential flow. It
 *   relays `Set-Cookie`, redirects only to a `safeRedirect`-validated target,
 *   and reports `401`, `429` and service faults as distinct failures.
 *
 * Both are typed against the parts of SvelteKit's `RequestEvent` they use, so
 * the package has no dependency on `@sveltejs/kit`.
 *
 * @module
 */

export * from "./Handle.ts";
export * from "./Actions.ts";
