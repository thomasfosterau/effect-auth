/**
 * The front-end half of effect-auth (`@thomasfosterau/effect-auth-client`): a
 * small, dependency-free vanilla client (`createAuthClient`) with typed methods
 * over the auth HTTP contract and an observable session store.
 *
 * The Svelte binding lives in its own package,
 * `@thomasfosterau/effect-auth-svelte`, which builds on this one.
 *
 * Wire types (`SessionWithUserView`, `SignUpPayload`, ...) come straight from
 * `@thomasfosterau/effect-auth`'s `Http` namespace; they erase at compile time,
 * so importing them costs the browser bundle nothing.
 */
export * from "./Client.ts";
