/**
 * SAML 2.0 service-provider support for effect-auth
 * (`@thomasfosterau/effect-auth/saml`).
 *
 * The root of `effect-auth` declares the `SamlVerifier` contract — parse and
 * cryptographically verify a SAML Response, build an `AuthnRequest`, render SP
 * metadata — but implements none of it: XML canonicalisation, XML-DSig and
 * DEFLATE need a dependency the rest of the core does not carry. This subpath
 * is the implementation, over
 * [`@node-saml/node-saml`](https://github.com/node-saml/node-saml), an
 * optional peer of `@thomasfosterau/effect-auth` that only this subpath
 * imports: install it to use `/saml`. The root barrel never reaches it
 * (`ModuleGraph.test.ts`).
 *
 * **Node-only.** `@node-saml/node-saml` needs Node APIs, so this subpath does
 * not run on Cloudflare Workers or in a browser; the rest of the core does.
 *
 * The flow — domain routing, one-time use, issuer checks, user provisioning,
 * sessions — stays in the root's `SSO` module, and only the XML job lives
 * here.
 *
 * ```ts
 * import { Layer } from "effect";
 * import * as Saml from "@thomasfosterau/effect-auth/saml";
 * import { SamlReplayStore, memorySamlReplayStore, SsoService } from "@thomasfosterau/effect-auth";
 *
 * const ssoLayer = SsoService.layer().pipe(
 *   Layer.provide(
 *     Layer.mergeAll(Saml.layer, Layer.succeed(SamlReplayStore)(memorySamlReplayStore())),
 *   ),
 * );
 * ```
 *
 * Behind more than one instance, replace `memorySamlReplayStore` with a shared
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
 * @module saml
 */
export * from "./Verifier.ts";
