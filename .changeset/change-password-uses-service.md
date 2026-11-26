---
"@thomasfosterau/effect-auth": patch
---

`PATCH /users/me/password` (`changePassword`) goes through the application's `EmailPasswordService`, so its configuration applies, rather than a default-configured one built per request that needed `EmailPasswordStore` and `UserStore` outside `AuthServices`.
