---
"@thomasfosterau/effect-auth": minor
---

Every sign-in method now consults the `SecondFactorGate`, not only the password methods: the magic link, the email and phone one-time codes, `redeemOneTimeTokenForSession`, the sign-in after an email verification, OAuth `signInWithCallback`, SSO (OIDC and SAML) and Google One Tap return the gate's challenge as `secondFactor`, and no session, for a user it requires a second factor of. Possession of a mailbox, phone or IdP account no longer skips an enrolled second factor.

`Email.exemptFromSecondFactor(...methods)` (the `SecondFactorExemptMethods` reference) lists the methods sufficient alone, for instance `"sso"` for an IdP that enforces its own multi-factor policy; it is empty by default. `Email.secondFactorChallenge(user, method)` is the check itself, for a host that issues a session on its own (after a passkey assertion, say).

Breaking: `MagicLinkResult`, `EmailOtpAuthResult`, `PhoneOtpAuthResult`, `OAuthSignInResult`, `SsoSignInResult`, `GoogleOneTapSignInResult` and `redeemOneTimeTokenForSession`'s result are now `SessionOrChallenge` unions: `session` and `token` are absent when `secondFactor` is present. Over HTTP, `POST /sessions` answers these methods' challenge with `202` as it does for passwords, `POST /email-verifications/redemptions` can answer `202` with the challenge, and the SSO callbacks answer `secondFactor` in the body without a session cookie.
