---
"@thomasfosterau/effect-auth": minor
"@thomasfosterau/effect-auth-resend": minor
---

Sends that would reveal whether an account exists now go through a host scheduler seam, and every other send is awaited inline again (#196).

- **`DeliveryScheduler`** is the host's way to run work after the response. `DeliveryScheduler.waitUntil(fn)` is for Cloudflare Workers' `ExecutionContext.waitUntil`, and `DeliveryScheduler.forkDetach` (the default) is a detached fiber for long-lived servers. Each send reads the scheduler from the calling fiber, so providing it per request works even when the services are built once.
- **Off the response path:** the sign-up verification email and existing-account notice, the magic link with `disableSignUp`, email OTP `sign-in` with `disableSignUp` and `forget-password`, phone OTP `sign-in` with `disableSignUp`, and the password-reset email. These flows hand the send to the scheduler whichever callback they were given. A failed send never fails the request: it is logged, counted on `effect_auth_delivery_sends_total`, and passed to the new `afterDeliveryFailure` hook, which `AuditPlugin` logs as `auth.deliveryFailure`. None of these record the message's token or code.
- **Inline again:** `emailCallbacks` / `smsCallbacks` await their send, so a failed magic link, code, verification email, change-email or delete-account mail, or second-factor code fails the flow that sent it, where existence isn't hidden. Previously every derived send was detached.
- A failed sign-up send no longer fails the sign-up with `EmailVerificationError`.
- `EmailVerificationService.createVerification` and `resendVerification` take an optional `{ offResponsePath }`.
- `EmailSender.logging` and `SmsSender.logging` are explicit development transports. They log each message's recipient and purpose and send nothing.
- `Testing.inlineDeliveryScheduler` runs detached sends in place for tests.
- The README's new "Delivery" section lists each flow's posture and the reason for it.

effect-auth-resend adds `layerConfig`, which reads `RESEND_API_KEY` (or a `Config` you pass) and fails the layer's construction when it is missing or empty. There is no no-op fallback; use `EmailSender.logging` explicitly in development.
