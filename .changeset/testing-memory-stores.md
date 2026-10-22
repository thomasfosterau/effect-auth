---
"@thomasfosterau/effect-auth": minor
---

`@thomasfosterau/effect-auth/testing` adds in-memory reference stores. `memoryStores` is one layer with sessions, users, identifiers, TOTP and OTP second factors, trusted devices, JWT keys, OAuth accounts and users, the four OIDC provider stores, and the `KeyValueStore`-backed token stores. Each store is also exported on its own as `memoryXStore()`. With them, a test or demo builds `SessionService`, `EmailPasswordService`, `MultiFactorService`, `OAuthService`, `JwtService` and `OidcProviderService` without a database. The JSDoc examples for `aes256GcmCipher`, `mcpProviderPreset`, `TrustedDeviceWithMultiFactorGateLayer`, `MultiFactorGateLayer`, `OtpSecondFactorGateLayer` and `TrustedDeviceWithOtpSecondFactorGateLayer` now build their layers over these stores and run.
