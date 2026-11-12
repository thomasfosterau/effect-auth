---
"@thomasfosterau/effect-auth": minor
---

Security fix: a sign-up can no longer set authority-bearing attributes (#580). An unauthenticated `POST /users` carrying `attributes: { role: "admin" }` created an admin, because `UserServiceConfig.serverOnlyAttributes` was enforced only on `updateUserAttributes`.

- **Breaking:** `POST /users` now keeps only the `attributes` keys named in the new `signUpAttributes` option of `Http.make` / `Http.makeAsync` (also the third argument of `groupLayers` and `usersGroupLayer`). The default is none, so a client that set attributes at sign-up must have them listed there. A key the list doesn't name is dropped without an error; the kept attributes may take at most `SIGN_UP_ATTRIBUTES_MAX_BYTES` (4096) bytes as UTF-8 JSON, and a larger bag is refused with `400`.
- `EmailPasswordService.signUp` (and so `UsernameService.signUp`) and `AuthLifecycleService.signUp` always drop, whatever the allow-list says and after the `beforeSignUp` hooks, the `UserService`'s server-only attributes (default `["role"]`) and the new `SIGN_UP_PROTECTED_ATTRIBUTES`: the ban keys (`banned`, `banReason`, `banExpires`), the SCIM keys (`scimUserName`, `scimDeactivated`, `scimExternalId`) and `isAnonymous`. Set those after the user exists, through `AdminService` or SCIM. Anti-enumeration stand-in users carry the same stripped attributes.
- `./client/testing`'s `makeServerFixture` takes `signUpAttributes` too.
