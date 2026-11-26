---
"@thomasfosterau/effect-auth": patch
---

`POST /email-verifications` hands an unverified account's send to the `DeliveryScheduler` instead of awaiting it, so neither the mail provider's round trip nor its failure (formerly a `500`) tells an unverified account from an unknown or verified address. A password-reset request for an unknown address now makes the same two store writes as one for a known address, of a marker row whose token nobody holds; `resetPassword` refuses a marker, and a repeat request replaces it.
