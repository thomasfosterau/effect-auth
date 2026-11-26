---
"@thomasfosterau/effect-auth": minor
---

WebAuthn supports only `none` attestation, and now says so. `RegistrationChallenge` carries `attestation: "none"` to pass to `navigator.credentials.create()`, and `WebAuthnConfig.attestation` accepts only `"none"` (the default): `"indirect"`, `"direct"` or `"enterprise"` makes the `WebAuthnService` layer build die with the new `WebAuthnConfigError`, since attestation statements are never verified.
