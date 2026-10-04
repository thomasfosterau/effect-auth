---
"@thomasfosterau/effect-auth": minor
---

The `password` cluster no longer exports `PasswordReset`'s raw `make` (#259). Through the barrel it surfaced as `Auth.Password.make` (and `make` from `@thomasfosterau/effect-auth/password`), which reads as the cluster's password hasher but built a `PasswordResetService`. Build the service with `PasswordResetService.layer(config)`, the same public constructor the `email/` and `multifactor/` services use. The rest of the password-reset surface (`PasswordResetService`, `PasswordResetStore`, `PasswordResetUserStore` and the `PasswordResetToken`, `PasswordResetConfig` and `PasswordResetResult` types) is unchanged.
