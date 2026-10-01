/**
 * The front-end half of effect-auth (`@thomasfosterau/effect-auth-client`): a
 * small, dependency-free vanilla client (`createAuthClient`) with typed methods
 * over the auth HTTP contract and an observable session store.
 *
 * Framework bindings live in their own packages —
 * `@thomasfosterau/effect-auth-react`, `@thomasfosterau/effect-auth-svelte`,
 * `@thomasfosterau/effect-auth-vue` and `@thomasfosterau/effect-auth-solid` —
 * each of which builds on this one.
 *
 * Wire types (`SessionWithUserView`, `SignUpPayload`, ...) come straight from
 * `@thomasfosterau/effect-auth`'s `Http` namespace; they erase at compile time,
 * so importing them costs the browser bundle nothing.
 */
export * from "./Client.ts";
