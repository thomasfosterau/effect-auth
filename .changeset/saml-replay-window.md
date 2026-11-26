---
"@thomasfosterau/effect-auth": patch
---

Two SAML replay fixes.

- `SsoService` keeps a spent assertion's replay record until its `NotOnOrAfter` plus `samlClockSkewMs`. The verifier accepts an assertion until then, but the record expired at `NotOnOrAfter`, so a captured assertion could be replayed during the skew window (3 minutes by default) when no request had to be spent.
- The `/saml` verifier takes `InResponseTo` only from signed content: the assertion's `SubjectConfirmationData`, or the `Response` attribute only when the Response signature is required (`wantAuthnResponseSigned`). Before, when the signed assertion named no request, the value came from the unsigned `Response` attribute, so an attacker could wrap such an assertion with the id of an `AuthnRequest` they had started and get past `allowIdpInitiated: false`. Such a response now reads as unsolicited, and is refused unless `allowIdpInitiated` is on.
