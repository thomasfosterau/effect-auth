---
"@thomasfosterau/effect-auth": minor
---

`MultiFactorService.enable` now fails with the new `MultiFactorAlreadyEnabledError` when the user already has a confirmed enrolment, instead of overwriting it unverified and leaving the account without a second factor until the new one was confirmed; `POST /multi-factor-enrollments` answers it `400`. Remove the enrolment with `disable` first. An enrolment that was never confirmed is still replaced.

The `docs: true` reference page loads Scalar at a pinned version with a Subresource Integrity hash, and the `./sql` WebAuthn challenge store reports an undecodable row as `AuthError` rather than a defect.
