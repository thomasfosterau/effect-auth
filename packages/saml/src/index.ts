/**
 * SAML 2.0 service-provider support for effect-auth.
 *
 * Core `effect-auth` declares the `SAMLVerifier` contract — parse and
 * cryptographically verify a SAML Response, build an `AuthnRequest`, render SP
 * metadata — but implements none of it: XML canonicalisation, XML-DSig and
 * DEFLATE are not things a dependency-free core can carry. This package is the
 * implementation, over
 * [`@node-saml/node-saml`](https://github.com/node-saml/node-saml).
 *
 * The split mirrors `PasswordHasher` (core) / `@thomasfosterau/effect-auth-argon2`
 * (adapter): the flow — domain routing, one-time use, issuer checks, user
 * provisioning, sessions — stays in core's `SSO` module, and only the XML job
 * lives here.
 *
 * ```ts
 * import { Layer } from "effect";
 * import * as SAML from "@thomasfosterau/effect-auth-saml";
 * import { SAMLReplayStore, memorySAMLReplayStore, SSOService } from "@thomasfosterau/effect-auth";
 *
 * const ssoLayer = SSOService.layer().pipe(
 *   Layer.provide(
 *     Layer.mergeAll(SAML.layer, Layer.succeed(SAMLReplayStore)(memorySAMLReplayStore())),
 *   ),
 * );
 * ```
 *
 * Behind more than one instance, replace `memorySAMLReplayStore` with a shared
 * implementation — a replay defence that only remembers what one process saw is
 * not a replay defence.
 *
 * ## Version floor
 *
 * `@node-saml/node-saml` is pinned to `^5.1.0` and must never be relaxed below
 * it. 5.1.0 is the release that fixed the July 2025 signature-scope
 * vulnerabilities (CVE-2025-54419, CVE-2025-54369), where a crafted document
 * could get profile data read from bytes the signature did not cover.
 *
 * @module effect-auth-saml
 */
export * from "./Verifier.ts";
