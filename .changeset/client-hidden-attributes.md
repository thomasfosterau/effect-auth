---
"@thomasfosterau/effect-auth": minor
---

The HTTP tier no longer hands a user's ban and SCIM attributes (`banned`, `banReason`, `banExpires`, `scimUserName`, `scimExternalId`, `scimDeactivated`) to the client. Every `users` resource and user view leaves out the keys of the new `Http.make` option `clientHiddenAttributes` (default `CLIENT_HIDDEN_ATTRIBUTES`; extend it with your own server-side keys, or pass `[]` for the old behaviour). The admin endpoints (`/admin/users`, `/user-bans`) still show the whole bag. `RemoteSession` reads the client view, so an app that authorizes on a hidden key over it needs that key left visible. The exported group layers read the `ClientHiddenAttributes` reference, which defaults to the same list.
