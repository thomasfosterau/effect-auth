---
"@thomasfosterau/effect-auth": minor
"@thomasfosterau/effect-auth-saml": patch
---

Core and effect-auth-saml no longer use the Node `Buffer` global outside the `node:crypto` corral (`password/Password.ts`, `TokenHash.ts`, `Cipher.ts`): encoding goes through `effect/encoding` (`Base64`, `Base64Url`, `Hex`), `TextEncoder` and `Uint8Array`, so these modules don't depend on a Node global in Workers and browsers (#481). Lint now rejects `Buffer` outside that corral and Node-only code.

**Breaking — the OTP primitives use `Uint8Array`, not `Buffer`.** `generateSecret` and `decodeBase32` resolve to a `Uint8Array`, and `encodeBase32`, `generateHotp`, `verifyHotp`, `generateTotp` and `verifyTotp` take one (a `Buffer` is still accepted, since it is a `Uint8Array`).

Decoding is now strict where `Buffer` was lenient: `constantTimeHashEqual` is `false` when either side is not hex (two different non-hex strings used to compare equal); a JWT segment that is not base64url fails as malformed; a session-cache cookie or `Authorization: Basic` value that is not base64 is ignored; a WebAuthn base64url value that does not decode reads as no bytes. effect-auth-saml drops whitespace from a `SAMLResponse` before decoding it, so a line-wrapped one is accepted, and rejects one that is not base64 with "SAMLResponse is not valid base64".
