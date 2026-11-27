---
"@thomasfosterau/effect-auth": minor
---

Add `ConfusablesPlugin`, an opt-in check that refuses a new email address which mixes scripts or passes for an ASCII address (UTS 39, Unicode 18.0 confusables).

- New hook point `beforeClaimEmail` (`ClaimEmailArgs`: `{ email, flow, userId? }`), fired with the normalized address by `EmailPasswordService.signUp`, by the magic-link and email OTP sign-ins that create a user, and by `AccountManagementService.requestEmailChange` after the current address is told. `requestEmailChange` resolves `Hooks` optionally.
- `ConfusablesPlugin({ restriction?, asciiLookalikes?, flows? })` guards it and fails with the new `ConfusableEmailError` (code `CONFUSABLE_EMAIL`), which joins `HookError`; the HTTP tier answers it `400`, including on `POST /email-changes`, which now also answers the other hook refusals as the other hook-guarded flows do.
- `skeleton`, `restrictionLevel` and `confusableEmailReason` are exported from `./plugins`.
