/**
 * `@thomasfosterau/effect-auth/client`: the dependency-free vanilla client
 * (`createAuthClient`) over the HTTP contract, with wire types from `./http`
 * that erase at compile time. Tests use the `./client/testing` fixture; the
 * root barrel re-exports neither.
 */
export * from "./Client.ts";
