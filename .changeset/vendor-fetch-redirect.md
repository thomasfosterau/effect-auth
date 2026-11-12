---
"@thomasfosterau/effect-auth-resend": patch
"@thomasfosterau/effect-auth-twilio": patch
---

Security: the Resend and Twilio senders no longer follow redirects or keep unbounded error bodies (#606). Every request is sent with `redirect: "error"`, so a 3xx fails the send as an `AuthError` without a second request and the credentials in `Authorization` are never replayed to the `Location`; the request also carries the fiber's `AbortSignal`, so interrupting a send cancels it. A non-2xx response's body is read only up to `MAX_ERROR_BODY_CHARS` (1024) characters, then cancelled, and the `AuthError`'s `cause.body` (and Twilio's message) keeps that excerpt, ending in `TRUNCATION_MARKER` when cut. A body that echoes the API key, the Twilio auth token or the Basic credentials has them replaced with `[redacted]`.
