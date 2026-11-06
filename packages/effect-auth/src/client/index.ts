/**
 * The front-end half of effect-auth (`@thomasfosterau/effect-auth/client`): a
 * small, dependency-free vanilla client (`createAuthClient`) with typed methods
 * over the auth HTTP contract and an observable session store.
 *
 * The Svelte binding lives in its own package,
 * `@thomasfosterau/effect-auth-svelte`, which builds on this subpath.
 *
 * Wire types (`SessionWithUserView`, `SignUpPayload`, ...) come straight from
 * the `./http` subpath; they erase at compile time, so importing them costs the
 * browser bundle nothing. The in-memory server fixture for tests is
 * `@thomasfosterau/effect-auth/client/testing`. The root barrel does not
 * re-export either.
 */
export * from "./Client.ts";
