---
"@thomasfosterau/effect-auth": minor
"@thomasfosterau/effect-auth-client": minor
---

**Breaking (HTTP):** account management is JSON:API resources (#205). The endpoints take `application/vnd.api+json` documents and answer JSON:API documents and error documents.

| Before                                         | Now                                                                                                                         |
| ---------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------- |
| `POST /change-password`                        | `PATCH /users/me/password` (a `user-passwords` document, id `me`): `204`                                                    |
| `POST /change-email` · `/change-email/confirm` | `POST /email-changes` (`202`) · `POST /email-changes/redemptions` (the token, `204`)                                        |
| `POST /delete-user` · `/delete-user/confirm`   | `POST /account-deletions` (`202`) · `POST /account-deletions/redemptions` (the token; `204`, the session cookies cleared)   |
| `POST /multi-factor/enable`                    | `POST /multi-factor-enrollments`: `201`, the unverified enrolment with `meta.secret`, `meta.totpUri` and `meta.backupCodes` |
| `POST /multi-factor/confirm`                   | `PATCH /multi-factor-enrollments/current` with the `code`: `200`, `verified: true`                                          |
| `POST /multi-factor/disable`                   | `DELETE /multi-factor-enrollments/current` with the password in `meta`: `204`                                               |
| `POST /multi-factor/regenerate-backup-codes`   | `POST /backup-code-sets`: `201`, the codes in `meta.backupCodes`                                                            |

- The confirmation tokens travel in the request body, never in a URL.
- effect-auth-client: `changePassword`, `changeEmail`, `deleteUser` and `multiFactor` keep their arguments and results and call the new endpoints.
