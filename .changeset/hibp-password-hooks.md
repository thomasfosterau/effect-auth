---
"@thomasfosterau/effect-auth": minor
---

Check every new password against Have I Been Pwned, and verify the current password through `MultiAlgorithmVerifier`.

- `HaveIBeenPwnedPlugin` reads a non-2xx answer (a `429`, a `503`, a challenge page) as the API being unavailable, so `failClosed: true` now refuses on it instead of allowing the password. It gives up after `timeout` (new option, default 5 seconds) and sends `Add-Padding: true`.
- New hook points `beforeChangePassword` and `beforeSetPassword` (`ChangePasswordArgs` / `SetPasswordArgs`: `{ userId, newPassword }`). `EmailPasswordService.changePassword` fires the first after the current password verifies, `setPassword` the second, and `HaveIBeenPwnedPlugin` guards both. `PATCH /users/me/password` answers a hook refusal as the other hook-guarded flows do (`400` for a breached password, `429` for a rate limit).
- `changePassword` and `MultiFactorService.enable`, `disable` and `regenerateBackupCodes` check the current password through `MultiAlgorithmVerifier` when it is present, as sign-in does, so after a hasher switch a user with a legacy hash no longer gets a `500`.
