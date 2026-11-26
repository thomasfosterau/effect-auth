---
"@thomasfosterau/effect-auth": minor
---

Make email and password changes safe by default. **Breaking:** `AccountManagementService.requestEmailChange(userId, newEmail, reauthentication)` takes a third argument, and `AccountManagementConfig` requires `sendEmailChangeNotice` (`emailCallbacks` derives it, purpose `"email-change-requested"`).

- Starting an email change re-authenticates: an account with a password gives `currentPassword` (`InvalidCredentialsError` when wrong); an account without one gives the session it is on, which must be its own, not an impersonation, and created within `reauthenticationMaxAge` (default 5 minutes). Otherwise it fails with the new `ReauthenticationRequiredError` (`REAUTHENTICATION_REQUIRED`). `POST /email-changes` takes `currentPassword`, answers `403` without re-authentication and `400` for a wrong password, and has a default IP rate limit (10 per 15 minutes).
- The current address is told at request time, naming the new address, before the new address is checked, whether or not it is free.
- `changePassword` (and `PATCH /users/me/password`) now revokes the user's other sessions and every trusted device by default; pass `revokeOtherSessions: false` to keep them.
- A password reset and disabling multi-factor revoke the user's trusted devices, when a `TrustedDeviceStore` is present.
