---
"@thomasfosterau/effect-auth": patch
---

`resendCooldown` answers a known and an unknown address alike in the passwordless flows that hide whether an account exists: magic-link, email OTP and phone OTP sign-in with `disableSignUp`, and email OTP `forget-password` (#415). A request for an address with no account stores an undelivered token or code as its cooldown marker, so a repeat within the window fails with `ResendTooSoonError` (HTTP 429, the same body and headers) exactly as it does for an account holder. The marker is never sent, a magic-link marker is a random 32-byte token, and an OTP marker is a 32-digit code, beyond reach of the attempt limit. Without `resendCooldown`, a request for an unknown address stores nothing.
