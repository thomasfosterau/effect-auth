---
"@thomasfosterau/effect-auth": patch
"@thomasfosterau/effect-auth-client": patch
"@thomasfosterau/effect-auth-drizzle": patch
"@thomasfosterau/effect-auth-resend": patch
"@thomasfosterau/effect-auth-saml": patch
"@thomasfosterau/effect-auth-sql": patch
"@thomasfosterau/effect-auth-twilio": patch
---

Internal refactor for the Effect lint presets, with these observable edges:

- `SessionService.createSession` / `setSessionAttributes`, `UserService.updateUserAttributes`, the `Username` sign-up and sign-in inputs and `ScimUserStore.create` take `Types.Attributes` (the readonly form of `Record<string, unknown>`); existing callers still type-check.
- OAuth userinfo, OIDC discovery, JWKS and id_token segments that are not JSON objects now fail with `OAuthProviderError`, and a malformed JWKS document fails with `JwtError("Failed to fetch JWKS")`, instead of a defect or a confusing later error.
- A CAPTCHA verification body of `null` now counts as a failed verification (`CaptchaError`) instead of a defect.
- The sql stores decode their JSON columns with Schema, so a malformed stored value fails with the same `AuthError` instead of passing through unchecked; `readRbacPolicies` (drizzle) may return policies in a different order (decisions are unchanged).
- Several thrown plain `Error`s (invalid header names, reserved principal types, malformed permissions, OTP URI and COSE key errors, session-cache config) are now tagged error classes with the same message; they are still `Error` instances.
- resend and twilio wrap a failed non-2xx body read in a private tagged defect; saml reads non-object attribute bags as empty.
- Effect handlers that became `Effect.fn` (auth middleware schemes, `requireScim`, JWT key rotation, decoy hashing) now emit a tracing span.
