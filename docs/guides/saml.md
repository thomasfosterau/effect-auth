# SAML (`/saml`)

SAML 2.0 service-provider support, as an Effect `Layer`.

SAML 2.0 service-provider support, as an Effect `Layer`.

The root of the core declares the `SamlVerifier` contract but implements none
of it: XML canonicalisation, XML-DSig verification and DEFLATE need a
dependency the rest of the core does not carry. This subpath is the
implementation, over [`@node-saml/node-saml`](https://github.com/node-saml/node-saml),
an **optional peer** of `@thomasfosterau/effect-auth` that only `/saml`
imports:

```sh
pnpm add @thomasfosterau/effect-auth @node-saml/node-saml effect
```

**`/saml` is Node-only.** node-saml needs Node APIs, so this subpath does not
run on Cloudflare Workers or in a browser; the rest of the core does. The root
barrel never reaches node-saml (`ModuleGraph.test.ts` pins it).

The **flow** stays in the root's `SsoService` — domain routing, one-time use of
the `AuthnRequest` and the assertion, issuer pinning, user provisioning,
sessions. Only the XML job lives here.

## Usage

```ts
import { Layer } from "effect";
import { FetchHttpClient } from "effect/http";
import * as Saml from "@thomasfosterau/effect-auth/saml";
import { SamlReplayStore, SsoService, memorySamlReplayStore } from "@thomasfosterau/effect-auth";

const samlSupport = Layer.mergeAll(
  Saml.layer,
  Layer.succeed(SamlReplayStore)(memorySamlReplayStore()),
);

// OIDC connections reach the IdP (discovery, token, userinfo, JWKS) through
// effect/http's HttpClient.
const ssoLayer = SsoService.layer().pipe(Layer.provide([samlSupport, FetchHttpClient.layer]));
```

Register a connection, then start and finish sign-ins:

```ts
import { Effect } from "effect";
import { SsoService } from "@thomasfosterau/effect-auth";

// Register once (admin-gated), with the IdP's signing certificate(s) pinned.
const register = (adminUserId: string, idpCertificatePem: string) =>
  Effect.gen(function* () {
    const sso = yield* SsoService;
    return yield* sso.registerSamlProvider(adminUserId, {
      protocol: "saml",
      domain: "acme.test",
      entityId: "https://idp.acme.test/metadata", // the IdP's Issuer
      ssoUrl: "https://idp.acme.test/sso", // HTTP-Redirect binding
      idpCertificates: [idpCertificatePem], // pinned; rotation-ready
      spEntityId: "https://app.test/saml/metadata",
      acsUrl: "https://app.test/api/auth/sso/saml/acs",
      organizationId: "org-1",
    });
  });

// Start: redirect the browser to `url`; the IdP echoes `state` back as RelayState.
const start = (email: string) =>
  Effect.gen(function* () {
    const sso = yield* SsoService;
    return yield* sso.signIn({ email });
  });

// Finish, at the ACS endpoint: verify the posted SAMLResponse and issue a session.
// `browserState` is the `state` this browser kept from `start` (a cookie you
// set), so a response only finishes in the browser that asked for it.
const finish = (
  providerId: string,
  samlResponse: string,
  relayState: string,
  browserState: string | undefined,
) =>
  Effect.gen(function* () {
    const sso = yield* SsoService;
    const { user, token, isNewUser } = yield* sso.handleSamlCallback(
      providerId,
      samlResponse,
      relayState,
      { browserState },
    );
    return { userId: user.id, sessionToken: token, isNewUser };
  });

export { register, start, finish };
```

`memorySamlReplayStore` is single-process. Behind more than one instance,
implement `SamlReplayStore` against shared storage — a replay defence that only
remembers what one process saw is not a replay defence. Both of its operations
must be atomic; the tag's docs spell out what that means.

## What gets checked

`verify` refuses a response unless all of the following hold. Every one is a
rejection, not a warning:

| Check                                                                 | Enforced by                 |
| --------------------------------------------------------------------- | --------------------------- |
| Signature verifies against a **pinned** certificate (never `KeyInfo`) | node-saml + xml-crypto      |
| Profile data read only from signature-covered bytes                   | node-saml `getVerifiedXml`  |
| At most one `Assertion` per `Response`                                | node-saml                   |
| No `ID` referring to more than one element                            | node-saml                   |
| `Assertion` signed (or the whole `Response`, if you disable that)     | node-saml                   |
| `Issuer` matches the connection's IdP entity id                       | node-saml + `/saml`         |
| `AudienceRestriction` contains the SP entity id                       | node-saml                   |
| `Conditions` `NotBefore`/`NotOnOrAfter`, within the clock-skew window | node-saml                   |
| `SubjectConfirmationData` `Recipient` equals the ACS URL              | `/saml`                     |
| `SubjectConfirmationData` `NotOnOrAfter`                              | `/saml`                     |
| `Destination` equals the ACS URL                                      | `/saml`                     |
| Signed `InResponseTo` agrees with the `Response` attribute            | `/saml`                     |
| `InResponseTo` read only from signed content                          | `/saml`                     |
| Signature/digest algorithms on an allow-list (SHA-256+ by default)    | `/saml`                     |
| HMAC signature methods refused outright                               | `/saml`                     |
| Encrypted assertions refused with an actionable message               | `/saml`                     |
| `AuthnRequest` and `Assertion` ids each spendable once                | core `SsoService`           |
| An SP-initiated response finishes only in the browser that started it | core `SsoService` + `/http` |

`src/saml/Verifier.test.ts` reproduces the corresponding attack shapes against
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

## API

- `layer: Layer<SamlVerifier>` — core's `SamlVerifier`, for the layer stack that builds `SsoService` (together with a `SamlReplayStore`).
- `verifier` — the same implementation as a plain object (`verify`, `buildAuthnRequest`, `spMetadataXml`), for a call site with no Effect context, such as a metadata script.
- `EMAIL_NAMEID_FORMAT` — the `emailAddress` NameID format, the default for `AuthnRequest`s and SP metadata.

Every failure is core's `SamlError`. The input and output types (`SamlVerifyInput`, `SamlAssertion`, `SamlAuthnRequestInput`, `SamlMetadataInput`, `SamlSignatureAlgorithm`) and the defaults `defaultSignatureAlgorithms` (SHA-256, SHA-512) and `defaultClockSkewMs` (3 minutes) are exported by `@thomasfosterau/effect-auth`.
