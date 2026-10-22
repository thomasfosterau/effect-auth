---
"@thomasfosterau/effect-auth": patch
---

`AdminService.createUser` normalises each of `AdminCreateUserInput.identifiers` for its type before claiming it, as it already did the primary email (#408): an email or username is trimmed and lower-cased, and a phone number goes through the new `AdminConfig.normalizePhoneNumber` (default: trim only, as `PhoneOtpConfig.normalizePhoneNumber`'s default; pass the same function to both). An extra address such as `Alice@Example.com ` is now stored as `alice@example.com`, so it collides with that address held by another user and sign-in by it finds it. A failing phone normaliser fails `createUser` before anything is written.
