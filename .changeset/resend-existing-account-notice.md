---
"@thomasfosterau/effect-auth-resend": patch
---

`defaultRender` renders the `"existing-account"` notice (#428): the subject "Someone tried to sign up with your email address" and a body saying that a sign-up was attempted with an address that already has an account, that nothing about the account changed, and that its holder can sign in or reset their password, or ignore the email. It previously fell through to "Action required" and "Please continue in the app.".
