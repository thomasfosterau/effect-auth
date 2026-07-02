/**
 * @effect-auth/siwe
 *
 * Sign-In With Ethereum (EIP-4361) signature verification for effect-auth,
 * backed by `@noble/curves` secp256k1 recovery. Provide
 * {@link SiweVerifierLayer} alongside effect-auth's `SiweServiceLayer` and
 * stores to enable the `/siwe/nonce` + `/sign-in/siwe` endpoints.
 *
 * @example
 * ```ts
 * import { SiweVerifierLayer } from "@effect-auth/siwe";
 * import { SiweServiceLayer } from "effect-auth";
 * import { Layer } from "effect";
 *
 * const siwe = Layer.mergeAll(
 *   SiweServiceLayer({ domain: "app.example.com" }),
 *   SiweVerifierLayer,
 *   // + your SiweNonceStore / SiweUserStore layers
 * );
 * ```
 */
export * from "./SiweVerifier.js";
