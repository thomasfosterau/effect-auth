# @thomasfosterau/effect-auth-saml

The core's `SamlVerifier` seam over `@node-saml/node-saml`: verify a SAML 2.0 `Response`, build an HTTP-Redirect `AuthnRequest`, render SP metadata. The SSO flow itself (routing, one-time use, issuer pinning, provisioning, sessions) is core's `SsoService`.

## Boundary

Archetype **Vendor adapter** (`.fallowrc.json` zone `vendor-adapters`, which may import `core` and `ladder`). Peer: `effect` (`catalog:peers`). Depends on `@thomasfosterau/effect-auth` and `@node-saml/node-saml` (`^5.1.0`): XML canonicalisation, XML-DSig and DEFLATE are the implementation, so the library is a dependency, as `hash-wasm` is for argon2. Its dependency surface is node-saml alone (`xml-crypto` is a dev dependency for fixtures). Unlike the fetch-based adapters it is not Workers-safe on its own: node-saml needs Node APIs.

## Invariants

- **Never relax `@node-saml/node-saml` below `5.1.0`**: the fix for CVE-2025-54419 / CVE-2025-54369 (profile data read from bytes the signature did not cover).
- **Trust only pinned certificates** (`idpCertificates`), never a `KeyInfo` in the document; profile data is read only from signature-covered XML.
- **Every check is a rejection, never a warning**: issuer, audience, `Conditions` window with `defaultClockSkewMs`, `Recipient` and `Destination` equal to the ACS URL, `SubjectConfirmationData` `NotOnOrAfter`, signed `InResponseTo` agreeing with the attribute, at most one `Assertion`, no duplicated `ID`.
- **Algorithms are allow-listed** (`defaultSignatureAlgorithms`: SHA-256 and SHA-512); HMAC signature methods are refused outright.
- **Encrypted assertions are refused** with an actionable message; there is no half-built decryption path.
- **Pre-flight scans are conservative**: they run over the whole decoded document before node-saml and reject if anything anywhere fails, decoys included. Don't narrow them to "the signed part".
- **The request-only placeholder certificate** (`REQUEST_ONLY_IDP_CERT`) is used only to build an `AuthnRequest`; `verify` always builds its own instance from the pinned certificates.
- **Replay is core's job** (`SamlReplayStore`, spent once per `AuthnRequest` and per `Assertion`); this package is stateless.
- Every failure is a `SamlError`. `Verifier.test.ts` reproduces each attack shape against hand-built signed fixtures; a new check gets a fixture.

## Terms

- **IdP / SP** — the identity provider that signs the assertion, and this application as the service provider (`spEntityId`, `acsUrl`).
- **ACS URL** — the assertion consumer service endpoint the `Response` is posted to.
- **RelayState** — the opaque `state` core issues with the `AuthnRequest`, echoed back by the IdP.
