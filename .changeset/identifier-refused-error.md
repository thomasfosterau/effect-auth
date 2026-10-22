---
"@thomasfosterau/effect-auth": minor
"@thomasfosterau/effect-auth-drizzle": minor
---

`IdentifierStore.create` gains a typed refusal, `IdentifierRefusedError`, for an identifier a store cannot hold by its own shape: a store that keeps one email per user refuses a second, and an emails-only store refuses any other type. `claimIdentifier` passes it through. SCIM answers it with `409` and `scimType: "uniqueness"` instead of a `500`, so a `userName` change on a one-email store reaches the IdP as a request to reconcile. The other flows (sign-up, email change, username, phone number, admin extras) report it as an `AuthError`, as before, through the new `refusalAuthError` (#379).

effect-auth-drizzle's `SingleTableIdentifierStore` raises `IdentifierRefusedError` where it raised `AuthError` for those two refusals; a user with no row is still an `AuthError`.
