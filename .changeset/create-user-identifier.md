---
"@thomasfosterau/effect-auth": minor
---

A store's `createUser` receives the login handle the user is created with, as an optional `identifier` (`NewUserIdentifier`: `type`, normalised `value`, `verified` and, when verified, `verifiedAt`) on `CreateUserInput`, `OAuthCreateUserInput`, `MagicLinkCreateUserInput`, `EmailOtpCreateUserInput`, `PhoneOtpCreateUserInput` and the `AdminUserStore.createUser` and `ScimUserStore.create` inputs. Email and password sign-up, magic link, email OTP and phone OTP sign-up, OAuth, SSO and Google One Tap first sign-in, SCIM provisioning (its `userName`) and admin creation (its primary email) pass it. A store that keeps the address on the user row writes it there on insert, so a `NOT NULL` address column works with core sign-up; a store that keeps identifiers in a table of their own ignores the field (#380).

`createUserWithIdentifier(identifiers, identifier, create)` creates the user and claims the handle: a claim that finds the handle already held by the new user succeeds with that record (marked verified when the flow asked for a verified handle), and a handle another user holds fails with `IdentifierTakenError`, both when the claim loses and when the store's unique index rejects the user row's insert.
