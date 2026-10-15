---
"@thomasfosterau/effect-auth": patch
---

With `antiEnumeration` off, `AuthLifecycleService.signUp` answers a sign-up for an address another user holds unverified with no session, `needsEmailVerification: true` and a stand-in user built only from the caller's input (#421): a random UUID for its `id`, the submitted `name` and `attributes`, no `image`, and one timestamp for both `createdAt` and `updatedAt`. The holder's id, profile and timestamps stay out of the response, both from `signUp` and from `POST /sign-up`. When `sendOnSignUp` is set, the holder's verification is re-issued to the address. An address held verified fails with `EmailInUseError` (`409` over HTTP). The `AuthLifecycleResult.identifier` docs describe each answer.
