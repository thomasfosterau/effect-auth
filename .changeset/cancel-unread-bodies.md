---
"@thomasfosterau/effect-auth": patch
"@thomasfosterau/effect-auth-resend": patch
"@thomasfosterau/effect-auth-twilio": patch
---

Cancel every response body that is not read, since under workerd an unread body holds the request's I/O open until it is cancelled: the Resend and Twilio senders now cancel a 2xx body (they already cancelled a redirect's), and cancel an error body they stopped reading at the excerpt limit without letting a failed cancel turn the `AuthError` into a defect; `Http.RemoteSession`'s `read` and `readApiKey` cancel the body of a `401` and of any other non-`200` answer. A cancel that fails is dropped and never replaces the outcome.
