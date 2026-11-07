---
"@thomasfosterau/effect-auth": patch
---

`./saml`: the tamper check on `InResponseTo` reads the values from the raw XML rather than from node-saml's `profile.inResponseTo` (#532). node-saml 5.2 fills that field from the signed confirmation data, so on 5.2 the check compared the signed value with itself and never fired. A rewritten Response attribute is rejected again on both 5.1 and 5.2. So is any second `InResponseTo` anywhere in the document that disagrees with the signed one.
