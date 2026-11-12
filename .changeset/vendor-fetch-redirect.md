---
"@thomasfosterau/effect-auth-resend": patch
"@thomasfosterau/effect-auth-twilio": patch
---

Security: the Resend and Twilio senders no longer follow redirects or keep unbounded error bodies (#606). Every request is sent with `redirect: "manual"` (workerd rejects `"error"`, so this is the value that works on Cloudflare Workers too), and any 3xx, status-0 or `"opaqueredirect"` response fails the send as an `AuthError` with `cause: { status }`: its body is cancelled unread, its `Location` is never read, and there is no second request, so the credentials in `Authorization` are never replayed to another URL. The request also carries the fiber's `AbortSignal`, so interrupting a send cancels it. A non-2xx response's body is read only up to `MAX_ERROR_BODY_CHARS` (1024) characters, then cancelled, and the `AuthError`'s `cause.body` (and Twilio's message) keeps that excerpt, ending in `TRUNCATION_MARKER` when cut; a body stream that fails mid-read is an `AuthError`, no longer a defect. A body that echoes the API key, the Twilio auth token or the Basic credentials has them replaced with `[redacted]`.
