---
"@thomasfosterau/effect-auth": minor
---

**Breaking (HTTP, client):** admin, impersonation, API keys, OIDC-provider clients, SSO registration and sign-in, JWT issuance and device approval are JSON:API resources (#205, slice 5). The endpoints take `application/vnd.api+json` documents and answer JSON:API documents and error documents.

| Before                                                         | Now                                                                                                                                                          |
| -------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| `POST /admin/users/list`                                       | `GET /admin/users?filter[email]=…&page[offset]=…&page[limit]=…`: `users` resources, `meta.total`                                                             |
| `POST /admin/users/set-role`                                   | `PATCH /admin/users/:id` with `role`                                                                                                                         |
| `POST /admin/users/remove` · `/admin/users/revoke-sessions`    | `DELETE /admin/users/:id` · `DELETE /admin/users/:id/sessions`: `204`                                                                                        |
| `POST /admin/users/ban` · `/admin/users/unban`                 | `POST /user-bans`, the user as the `user` relationship (`201`: the ban, its id the user's, the user included) · `DELETE /user-bans/:id` (`204`)              |
| `POST /admin/impersonate` · `/admin/stop-impersonating`        | `POST /impersonations`, the user as the `user` relationship (`201`, the session cookie swapped) · `DELETE /impersonations/current` (`204`)                   |
| `GET` · `POST /api-keys` · `PATCH` · `DELETE /api-keys/:keyId` | The same paths as JSON:API: `api-keys` resources; the create answers `201` with the plaintext key in `meta.key`                                              |
| `GET /oauth2/clients` · `POST /oauth2/register`                | `GET` · `POST /oauth-clients` (`201`, a confidential client's secret in `meta.clientSecret`); the client's `type` is the `clientType` attribute              |
| `PATCH` · `DELETE /oauth2/clients/:clientId`                   | `PATCH` · `DELETE /oauth-clients/:id`                                                                                                                        |
| `POST /sso/register`                                           | `POST /sso-providers` (`201`): an `sso-providers` resource, `organizationId` as the `organization` relationship                                              |
| `POST /sign-in/sso`                                            | `POST /sso-authorizations` (`201`): the IdP `url`, the round-trip state as the id                                                                            |
| `GET /token`                                                   | `POST /tokens` (`201`): `token` and `expiresAt`, the id the token's SHA-256 digest                                                                           |
| `POST /device/approve` · `/device/deny`                        | `POST /device-authorizations/decisions` with `userCode` and `decision` (`approved`, which needs the session, or `denied`): `204`; the code stays in the body |

- **Left as they are**, because their wire format is fixed by a specification: RFC 8628's `POST /device/code` and `/device/token`, the SSO callbacks (`POST /sso/callback`, `POST /sso/saml/acs/:providerId`, `GET /sso/saml/metadata/:providerId`), the JWKS (`/jwks`, `/.well-known/jwks.json`), and the OIDC provider's `/oauth2/authorize`, `/oauth2/consent`, `/oauth2/token`, `/oauth2/userinfo`, RFC 7591 / 7592 `/register` and RFC 8414 discovery.
- **Discovery:** the OIDC provider's `/.well-known/openid-configuration` and `/.well-known/oauth-authorization-server` advertise `registration_endpoint` only while dynamic registration is enabled. They used to name the admin-gated `/oauth2/register`, which was never an RFC 7591 endpoint and is gone.
- **CSRF:** minting a JWT is now a `POST`, so the trusted-origin check covers it like every other write; the special case that treated `GET /token` as state-changing is removed.
- **`DELETE /impersonations/current` answers `404` on a session that is not an impersonation**; `POST /admin/stop-impersonating` signed any session out. Ending an impersonation also drops the session from a multi-session device list, as `DELETE /sessions/current` does.
- Permissions and refusal statuses are unchanged: admin calls need `isAdmin` (`403`), an unknown user answers `400`, a key the caller does not own `400`, an unknown or statically configured OAuth client `400`. No store contract changes: every resource is addressed by an id the stores already keep.
- `./client`: the methods keep their arguments and results and call the new endpoints, except `admin.unbanUser`, which now resolves with nothing (the lifted ban answers `204`, not the user).
