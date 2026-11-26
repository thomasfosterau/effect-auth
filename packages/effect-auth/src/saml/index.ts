/**
 * `@thomasfosterau/effect-auth/saml`: the `SamlVerifier` implementation, over
 * the optional peer `@node-saml/node-saml` (never below 5.1.0). It is
 * Node-only; the SSO flow stays in the root. Behind several instances, replace
 * `memorySamlReplayStore` with a shared store.
 *
 * @module saml
 */
export * from "./Verifier.ts";
