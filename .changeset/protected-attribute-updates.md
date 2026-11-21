---
"@thomasfosterau/effect-auth": patch
---

`UserService.updateUserAttributes` refuses the ban keys (`banned`, `banReason`, `banExpires`), the SCIM keys (`scimUserName`, `scimDeactivated`, `scimExternalId`) and `isAnonymous` with `InvalidInputError`, as sign-up already strips them, whatever `serverOnlyAttributes` says. Before, a server-side caller could clear a ban by writing `banned: false`. `AdminService`, `ScimService` and `AnonymousService` keep writing these keys through `UserServiceStore`.
