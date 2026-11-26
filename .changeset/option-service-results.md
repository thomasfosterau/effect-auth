---
"@thomasfosterau/effect-auth": minor
---

**Breaking:** the public results and fields that answered `null` for "nothing" now answer an `Option`:

- `primaryEmail`, `primaryEmailValue`, `anyEmail` and `anyEmailValue` return `Option<Identifier>` / `Option<string>`, and `getPhoneNumber` resolves to `Option<string>`.
- `MultiFactor.verifyTotp` resolves to `Option<number>`, the matched time step, `None` for a wrong code.
- `TrustedDeviceService.verify` resolves to `Option<string>`, the device's user id.
- `OrganizationService.provisionJitMembership` resolves to `Option<Member>`.
- `ManagedUser.provisionedBy` returns `Option<ProvisionedBy>`.
- `Entity.getEntity` and `Entity.getAttribute` return an `Option`.
- `decodeSessionCacheCookie` and `aes256GcmOpen` resolve to an `Option`.
- `AccountManagementConfig.sendDeleteAccountVerification` receives `email: Option<string>`, and `notifyEmailChanged` receives `oldEmail: Option<string>`.
