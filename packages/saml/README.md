# @thomasfosterau/effect-auth-saml

SAML 2.0 service-provider support for
[`@thomasfosterau/effect-auth`](../effect-auth), as an Effect `Layer`.

Core effect-auth declares the `SamlVerifier` contract but implements none of it:
XML canonicalisation, XML-DSig verification and DEFLATE are not things a
dependency-free core can carry. This package is the implementation, over
[`@node-saml/node-saml`](https://github.com/node-saml/node-saml) — the same
split as `PasswordHasher` (core) and
[`@thomasfosterau/effect-auth-argon2`](../argon2) (adapter).

The **flow** stays in core's `SSO` module — domain routing, one-time use of the
`AuthnRequest` and the assertion, issuer pinning, user provisioning, sessions.
Only the XML job lives here.

## Install

```sh
pnpm add @thomasfosterau/effect-auth-saml @thomasfosterau/effect-auth effect
```

## Usage

```ts
import { Layer } from "effect";
import * as Saml from "@thomasfosterau/effect-auth-saml";
import { SamlReplayStore, SsoService, memorySamlReplayStore } from "@thomasfosterau/effect-auth";

const samlSupport = Layer.mergeAll(
  Saml.layer,
  Layer.succeed(SamlReplayStore)(memorySamlReplayStore()),
);

const ssoLayer = SsoService.layer().pipe(Layer.provide(samlSupport));
```

Register a connection, then start and finish sign-ins:

```ts
Effect.gen(function* () {
  const sso = yield* SsoService;

  const provider = yield* sso.registerSamlProvider(adminUserId, {
    protocol: "saml",
    domain: "acme.test",
    entityId: "https://idp.acme.test/metadata", // the IdP's Issuer
    ssoUrl: "https://idp.acme.test/sso", // HTTP-Redirect binding
    idpCertificates: [pemFromTheIdP], // pinned; rotation-ready
    spEntityId: "https://app.test/saml/metadata",
    acsUrl: "https://app.test/api/auth/sso/saml/acs",
    organizationId: "org-1",
  });

  // Redirect the browser to `url`; the IdP echoes `state` back as RelayState.
  const { url, state } = yield* sso.signIn({ email: "worker@acme.test" });

  // …then, at the ACS endpoint:
  return yield* sso.handleSamlCallback(provider.id, SAMLResponse, RelayState);
});
```

`memorySamlReplayStore` is single-process. Behind more than one instance,
implement `SamlReplayStore` against shared storage — a replay defence that only
remembers what one process saw is not a replay defence. Both of its operations
must be atomic; the tag's docs spell out what that means.

## What gets checked

`verify` refuses a response unless all of the following hold. Every one is a
rejection, not a warning:

| Check                                                                 | Enforced by                |
| --------------------------------------------------------------------- | -------------------------- |
| Signature verifies against a **pinned** certificate (never `KeyInfo`) | node-saml + xml-crypto     |
| Profile data read only from signature-covered bytes                   | node-saml `getVerifiedXml` |
| At most one `Assertion` per `Response`                                | node-saml                  |
| No `ID` referring to more than one element                            | node-saml                  |
| `Assertion` signed (or the whole `Response`, if you disable that)     | node-saml                  |
| `Issuer` matches the connection's IdP entity id                       | node-saml + this package   |
| `AudienceRestriction` contains the SP entity id                       | node-saml                  |
| `Conditions` `NotBefore`/`NotOnOrAfter`, within the clock-skew window | node-saml                  |
| `SubjectConfirmationData` `Recipient` equals the ACS URL              | this package               |
| `SubjectConfirmationData` `NotOnOrAfter`                              | this package               |
| `Destination` equals the ACS URL                                      | this package               |
| Signed `InResponseTo` agrees with the `Response` attribute            | this package               |
| Signature/digest algorithms on an allow-list (SHA-256+ by default)    | this package               |
| HMAC signature methods refused outright                               | this package               |
| Encrypted assertions refused with an actionable message               | this package               |
| `AuthnRequest` and `Assertion` ids each spendable once                | core `SsoService`          |

`src/Verifier.test.ts` reproduces the corresponding attack shapes against
hand-built, signed XML fixtures.

## Encrypted assertions

Not supported in this version. Configure the IdP for **signed, unencrypted**
assertions delivered over TLS; a half-implemented decryption path is worth less
than a clear refusal.

## Version floor

`@node-saml/node-saml` is pinned to `^5.1.0` and must never be relaxed below it.
5.1.0 is the release that fixed the July 2025 signature-scope vulnerabilities
(CVE-2025-54419, CVE-2025-54369), where a crafted document could get profile
data read from bytes the signature did not cover.

## License

MIT
