---
"@thomasfosterau/effect-auth": minor
"@thomasfosterau/effect-auth-client": minor
"@thomasfosterau/effect-auth-sveltekit": minor
"@thomasfosterau/effect-auth-react": minor
"@thomasfosterau/effect-auth-svelte": minor
"@thomasfosterau/effect-auth-solid": minor
"@thomasfosterau/effect-auth-vue": minor
---

**Breaking (HTTP):** sign-in, sign-up and the flows that prove an address are JSON:API resources (#205). They take `application/vnd.api+json` documents and answer JSON:API documents and error documents.

| Before                                                                                                                                                  | Now                                                                                                                                                                                       |
| ------------------------------------------------------------------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `POST /sign-in`, `/sign-in/username`, `/sign-in/email-otp`, `/sign-in/phone-otp`, `/sign-in/anonymous`, `/sign-in/google-one-tap`, `/magic-link/verify` | `POST /sessions`, its write-only `credential` attribute tagged by `method` (`password`, `username`, `email-otp`, `phone-otp`, `anonymous`, `google-one-tap` with `idToken`, `magic-link`) |
| `POST /multi-factor/verify-totp`, `/multi-factor/verify-backup-code`                                                                                    | `POST /second-factor-challenges/:id/verifications` (`method`: `totp` / `backup-code`)                                                                                                     |
| `POST /sign-up`                                                                                                                                         | `POST /users`                                                                                                                                                                             |
| `POST /email-otp/send`, `/phone-otp/send`, `/magic-link/send`                                                                                           | `POST /otp-challenges` (`channel`: `email` / `phone` / `magic-link`)                                                                                                                      |
| `POST /email-verification/send` · `/email-verification/verify`                                                                                          | `POST /email-verifications` · `PATCH /email-verifications/:id` (the token)                                                                                                                |
| `POST /password-reset/request` · `/password-reset/reset`                                                                                                | `POST /password-resets` · `PATCH /password-resets/:id` (the token)                                                                                                                        |
| `GET /sign-in/google-one-tap/nonce`                                                                                                                     | `POST /google-one-tap-nonces` (the nonce is the resource's id)                                                                                                                            |

- A sign-in or sign-up that issues a session answers `201` with the `sessions` resource, its user in `included` and `meta.needsEmailVerification`. One that issues none answers `202`: with the `second-factor-challenges` resource to redeem, or with only `meta.needsEmailVerification` when the address must be verified first. The second-factor answer no longer carries the user.
- Under `antiEnumeration`, `POST /users` answers a fresh address and a held one with the same `202` and no user at all, so neither answer names an id (#195, #414).
- The sends (`otp-challenges`, `email-verifications`, `password-resets`) answer `202` with no body; a password reset answers `204`; an email verification answers `200` with the session when it signs the user in, else `204`.
- The default IP rate-limit rules follow the paths: `POST /sessions` (every sign-in method, now including magic-link verification), `POST /users`, `POST /otp-challenges`, `POST /password-resets` and the second-factor verifications.
- effect-auth-client: the sign-in, sign-up and verification methods keep their arguments and resolve with the new `AuthResult`, whose `user` is present only when a session was issued. `continueChallenge` takes an `AuthResult`. The framework bindings' form `AuthSuccess` type follows it.
- effect-auth-sveltekit: `credentialAction` sends its body as `application/vnd.api+json` by default (`contentType` overrides it), so an action for `POST /sessions` posts a `sessions` document.
