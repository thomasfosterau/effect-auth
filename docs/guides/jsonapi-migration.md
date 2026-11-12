# Migrating to the JSON:API HTTP tier

The included HTTP API is JSON:API (#205, [ADR-0024](../adr/0024-json-api-http-tier.md)). Every endpoint effect-auth designs now takes and answers `application/vnd.api+json` documents and fails with JSON:API error documents; the endpoints whose wire format another specification fixes (the RFC tier) are unchanged. This guide maps every route that went away to its replacement, and lists the store-contract, client and status-code changes that came with them.

The conversion landed in six slices. Slices 1 to 3 (sessions and identifiers, sign-in and sign-up, account management) were already in `@thomasfosterau/effect-auth` 0.1.0, so an app on 0.1.0 or 0.2.0 has them; the tables mark them **0.1.0**. Slices 4 and 5 (organizations, teams, admin, API keys, OIDC clients, SSO, tokens, device approval) arrive in the release after 0.2.0, marked **next**. An app and the auth service it talks to, through `./client`, `Http.RemoteSession` or the SvelteKit binding, must be on the same release.

The complete current surface is the [endpoint reference](../../packages/effect-auth/README.md#http-endpoint-reference) in the core README.

## What every converted endpoint does differently

- **Bodies are JSON:API documents.** A write sends `{ "data": { "type": "<type>", "attributes": { … } } }` (with `relationships` where one record names another) as `application/vnd.api+json`; another media type is `415`, and an `Accept` that rules JSON:API out is `406`. Answers are documents too: `data` is a resource object (or an array of them), related records come in `included`, and one-time values such as a new API key's plaintext come in `meta`.
- **Errors are JSON:API error documents**: `{ "errors": [{ "status", "detail", "meta": { "message", "code" } }] }`, `detail` the message and `code` the stable code of the domain error, when it has one. `./client`'s `AuthClientError.message` reads `detail`.
- **Records are addressed by their stored id.** A session is named by its stored id (the token's hash), never the token; a membership, team membership, role definition and domain claim by their own `id`.
- **No secret travels in a URL.** Reset, verification, account-change, second-factor and device user codes go in the request body.

## Every endpoint that moved

### Sessions, identifiers and the profile (0.1.0)

| Before                              | Now                                                  |
| ----------------------------------- | ---------------------------------------------------- |
| `GET /session`                      | `GET /sessions/current?include=user`                 |
| `POST /sign-out`                    | `DELETE /sessions/current`                           |
| `GET /sessions`                     | `GET /sessions` (a collection document)              |
| `DELETE /sessions/:sessionId`       | `DELETE /sessions/:id`, the id `GET /sessions` lists |
| `POST /sessions/revoke-others`      | `DELETE /sessions?filter[current]=false`             |
| `GET /identifiers`                  | `GET /identifiers` (the identifier's type is `kind`) |
| `DELETE /identifiers/:identifierId` | `DELETE /identifiers/:id`                            |
| `PATCH /user`                       | `PATCH /users/me` (only `name` and `image` writable) |

### Sign-in, sign-up and address proofs (0.1.0)

| Before                                                                                                                                 | Now                                                                                                                                                          |
| -------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| `POST /sign-in` · `/sign-in/username` · `/sign-in/email-otp` · `/sign-in/phone-otp` · `/sign-in/anonymous` · `/sign-in/google-one-tap` | `POST /sessions`, the write-only `credential` attribute tagged by `method` (`password`, `username`, `email-otp`, `phone-otp`, `anonymous`, `google-one-tap`) |
| `POST /magic-link/verify`                                                                                                              | `POST /sessions` with `credential.method: "magic-link"`                                                                                                      |
| `POST /multi-factor/verify-totp` · `/multi-factor/verify-backup-code`                                                                  | `POST /second-factor-challenges/verifications` (`method` `totp` or `backup-code`, the challenge as a relationship)                                           |
| `POST /sign-up`                                                                                                                        | `POST /users`                                                                                                                                                |
| `POST /email-otp/send` · `/phone-otp/send` · `/magic-link/send`                                                                        | `POST /otp-challenges` (`channel`: `email`, `phone`, `magic-link`)                                                                                           |
| `POST /email-verification/send` · `/email-verification/verify`                                                                         | `POST /email-verifications` · `POST /email-verifications/redemptions` (the token in the body)                                                                |
| `POST /password-reset/request` · `/password-reset/reset`                                                                               | `POST /password-resets` · `POST /password-resets/redemptions` (the token in the body)                                                                        |
| `GET /sign-in/google-one-tap/nonce`                                                                                                    | `POST /google-one-tap-nonces` (the nonce is the resource's id)                                                                                               |

### Account management (0.1.0)

| Before                                         | Now                                                                 |
| ---------------------------------------------- | ------------------------------------------------------------------- |
| `POST /change-password`                        | `PATCH /users/me/password`                                          |
| `POST /change-email` · `/change-email/confirm` | `POST /email-changes` · `POST /email-changes/redemptions`           |
| `POST /delete-user` · `/delete-user/confirm`   | `POST /account-deletions` · `POST /account-deletions/redemptions`   |
| `POST /multi-factor/enable`                    | `POST /multi-factor-enrollments` (the secret and codes in `meta`)   |
| `POST /multi-factor/confirm`                   | `PATCH /multi-factor-enrollments/current` with the `code`           |
| `POST /multi-factor/disable`                   | `DELETE /multi-factor-enrollments/current` (the password in `meta`) |
| `POST /multi-factor/regenerate-backup-codes`   | `POST /backup-code-sets`                                            |

### Device sessions and organizations (next)

| Before                                                                          | Now                                                                                         |
| ------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------- |
| `GET /multi-session/list`                                                       | `GET /device-sessions` (`active` marks the current one, users in `included`)                |
| `POST /multi-session/set-active`                                                | `PATCH /device-sessions/active` with a `device-sessions` linkage                            |
| `POST /multi-session/revoke`                                                    | `DELETE /device-sessions/:id`                                                               |
| `POST /organization/create`                                                     | `POST /organizations`                                                                       |
| `GET` · `PATCH` · `DELETE /organization/:organizationId`                        | `GET` · `PATCH` · `DELETE /organizations/:id` (members at `GET /organizations/:id/members`) |
| `PUT /organization/:organizationId/default-role`                                | `PATCH /organizations/:id` with `defaultRole`                                               |
| `POST /organization/set-active`                                                 | `PATCH /organizations/active` with an `organizations` linkage, or `data: null`              |
| `POST /organization/:organizationId/members`                                    | `POST /organizations/:id/members`, the user as the `user` relationship                      |
| `PATCH /organization/:organizationId/members` (by `userId`)                     | `PATCH /organization-members/:id` with `role`                                               |
| `POST /organization/:organizationId/members/:userId/deactivate` · `/reactivate` | `PATCH /organization-members/:id` with `status` `inactive` · `active`                       |
| `DELETE /organization/:organizationId/members/:userId`                          | `DELETE /organization-members/:id`                                                          |
| `GET` · `POST /organization/:organizationId/invitations`                        | `GET` · `POST /organizations/:id/invitations`                                               |
| `POST /invitations/:invitationId/accept` · `/reject` · `/cancel`                | `PATCH /invitations/:id` with `status` `accepted` · `rejected` · `canceled`                 |
| `POST /invitations/:invitationId/resend`                                        | `POST /invitations/:id/deliveries`                                                          |
| `GET` · `POST /organization/:organizationId/domains`                            | `GET` · `POST /organizations/:id/domains`                                                   |
| `DELETE /organization/:organizationId/domains/:domainId`                        | `DELETE /organization-domains/:id`                                                          |
| `POST /organization/:organizationId/domains/:domainId/verify`                   | `POST /organization-domains/:id/verifications`                                              |
| `GET /organization/:organizationId/roles`                                       | `GET /organizations/:id/roles`                                                              |
| `PUT /organization/:organizationId/roles/:role`                                 | `POST /organizations/:id/roles` (create) · `PATCH /organization-roles/:id` (replace)        |
| `DELETE /organization/:organizationId/roles/:role`                              | `DELETE /organization-roles/:id`                                                            |
| `GET` · `POST /organization/:organizationId/teams`                              | `GET` · `POST /organizations/:id/teams`                                                     |
| `PATCH` · `DELETE /teams/:teamId`                                               | `PATCH` · `DELETE /teams/:id`                                                               |
| `GET` · `POST /teams/:teamId/members`                                           | `GET` · `POST /teams/:id/members`, the user as the `user` relationship                      |
| `DELETE /teams/:teamId/members/:userId`                                         | `DELETE /team-members/:id`                                                                  |
| `GET /organization/:organizationId/members/:userId/teams`                       | `GET /organization-members/:id/teams`                                                       |

### Admin, API keys, OIDC clients, SSO, tokens and device approval (next)

| Before                                                         | Now                                                                                                         |
| -------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------- |
| `POST /admin/users/list`                                       | `GET /admin/users?filter[email]=…&page[offset]=…&page[limit]=…` (`meta.total`)                              |
| `POST /admin/users/set-role`                                   | `PATCH /admin/users/:id` with `role`                                                                        |
| `POST /admin/users/remove` · `/admin/users/revoke-sessions`    | `DELETE /admin/users/:id` · `DELETE /admin/users/:id/sessions`                                              |
| `POST /admin/users/ban` · `/admin/users/unban`                 | `POST /user-bans`, the user as the `user` relationship · `DELETE /user-bans/:id`                            |
| `POST /admin/impersonate` · `/admin/stop-impersonating`        | `POST /impersonations`, the user as the `user` relationship · `DELETE /impersonations/current`              |
| `GET` · `POST /api-keys` · `PATCH` · `DELETE /api-keys/:keyId` | The same paths as JSON:API `api-keys` resources; the new key's plaintext in `meta.key`                      |
| `GET /oauth2/clients` · `POST /oauth2/register`                | `GET` · `POST /oauth-clients` (a confidential client's secret in `meta.clientSecret`)                       |
| `PATCH` · `DELETE /oauth2/clients/:clientId`                   | `PATCH` · `DELETE /oauth-clients/:id`                                                                       |
| `POST /sso/register`                                           | `POST /sso-providers` (the organization is `relationships.organization`, not an `organizationId` attribute) |
| `POST /sign-in/sso`                                            | `POST /sso-authorizations` (the IdP `url`; the round-trip state as the id)                                  |
| `GET /token`                                                   | `POST /tokens` (`token` and `expiresAt`)                                                                    |
| `POST /device/approve` · `/device/deny`                        | `POST /device-authorizations/decisions` with `userCode` and `decision`                                      |

### Unchanged: the RFC tier

`POST /device/code`, `POST /device/token`, `GET /oauth2/authorize`, `POST /oauth2/consent`, `POST /oauth2/token`, `GET /oauth2/userinfo`, `POST /register` and `/register/:clientId`, `/.well-known/openid-configuration`, `/.well-known/oauth-authorization-server`, `/jwks`, `/.well-known/jwks.json`, `POST /sso/callback`, `POST /sso/saml/acs/:providerId`, `GET /sso/saml/metadata/:providerId` and `/scim/v2/*` keep their paths and wire formats. One change: the discovery documents advertise `registration_endpoint` (`/register`) only while dynamic registration is enabled. They used to name the admin-gated `/oauth2/register`, which was never an RFC 7591 endpoint.

## Status codes

| Request                                                                                                      | Before                   | Now                                                           |
| ------------------------------------------------------------------------------------------------------------ | ------------------------ | ------------------------------------------------------------- |
| A sign-in or sign-up that issues a session                                                                   | `200`                    | `201`, the `sessions` resource                                |
| A sign-in that needs a second factor, or an address to verify first                                          | `200`                    | `202`, the `second-factor-challenges` resource or only `meta` |
| Sign-up under `antiEnumeration`, for a fresh or a held address                                               | `200`                    | `202` for both, no user                                       |
| The sends (`otp-challenges`, `email-verifications`, `password-resets`, `email-changes`, `account-deletions`) | `200` `{ status: true }` | `202`, no body                                                |
| A password reset, email-change or account-deletion redemption                                                | `200`                    | `204`                                                         |
| An email-verification redemption                                                                             | `200`                    | `201` with the session when it signs in, else `204`           |
| Revoking, deleting or removing a record (sessions, members, teams, keys, …)                                  | `200`                    | `204`                                                         |
| A foreign or unknown session or identifier                                                                   | `400`                    | `404`                                                         |
| Removing an account's last identifier                                                                        | `400`                    | `403`                                                         |
| An unknown membership, team membership, role definition or domain claim id                                   | not `404`                | `404` (an unknown team id is still `403`)                     |
| Defining a role the organization already defines                                                             | `200` (replaced it)      | `409`; replace it with `PATCH /organization-roles/:id`        |
| Resending an invitation                                                                                      | `200`                    | `202` with the invitation                                     |
| Ending an impersonation on a session that is not one                                                         | `200` (signed it out)    | `404`                                                         |
| A body that is not `application/vnd.api+json`, or an `Accept` without it                                     | (accepted)               | `415` · `406`                                                 |

Permission refusals are unchanged: `401` without a session, `403` for an admin call without `isAdmin` or an organization call the actor's role does not permit, and `404` for a server module that is not configured.

## Store contracts

Only the organization store changed, where an item URL needed an id the stores did not keep (next):

- `OrganizationStore.getMemberById(memberId)` answers the membership with that `Member.id`, in any organization, or `null`.
- `TeamMember` and `OrgRole` gain an `id`. `OrganizationStore.addTeamMember` takes the whole `TeamMember` record (its id minted by the caller) instead of `(teamId, userId)`.
- `OrganizationStore.getTeamMemberById(teamMemberId)` and `getOrgRoleById(orgRoleId)` answer the record with that id or `null`. `upsertOrgRole` is still keyed by `(organizationId, role)`; the service passes the stored id when it replaces a definition, so a definition keeps its id.
- `OrganizationService` gains `getMemberById`, `getTeamMemberById`, `getOrgRoleById` and `getDomainById`.

A store of your own must add the three lookups, store the two ids and take the new `addTeamMember`. `Testing.organizationStoreConformance()` (`@thomasfosterau/effect-auth/testing`) checks the whole membership, team-membership and role contract by id; run it against your implementation. The memory, `./sql`, drizzle and Alchemy stores already implement it.

## `./client` and the bindings

The client's methods call the new endpoints; most keep their arguments and results. The ones that changed:

| Method                                                                                                      | Change                                                                                                    |
| ----------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------- |
| `revokeSession(id)` (0.1.0)                                                                                 | Takes the id `listSessions()` reports (the stored id), not the token                                      |
| `signIn`, `signUp`, the passwordless and verification methods (0.1.0)                                       | Resolve with `AuthResult`, whose `user` is present only when a session was issued                         |
| `continueChallenge` (0.1.0)                                                                                 | Takes an `AuthResult`                                                                                     |
| `multiSession.setActive` · `revoke`                                                                         | Take the `session.id` `multiSession.list()` answers, now the stored id                                    |
| `organization.updateMemberRole(memberId, { role })`, `removeMember`, `deactivateMember`, `reactivateMember` | Take the membership's own `id` (from `get(…).members` or `addMember`), not `(organizationId, userId)`     |
| `organization.removeDomain(domainId)` · `verifyDomain(domainId)`                                            | Take the claim's `id` alone                                                                               |
| `organization.upsertRole`                                                                                   | Replaced by `createRole(organizationId, { role, permissions })` and `updateRole(roleId, { permissions })` |
| `organization.deleteRole(roleId)`                                                                           | Takes the definition's `id`                                                                               |
| `organization.listTeamsForMember(memberId)`                                                                 | Takes the membership's `id`                                                                               |
| `organization.removeTeamMember(teamMemberId)`                                                               | Takes the team membership's `id` (from `addTeamMember` or `listTeamMembers`)                              |
| `admin.unbanUser`                                                                                           | Resolves with nothing (the lifted ban is a `204`)                                                         |

`Http.UpdateMemberRolePayload` is `{ role }` (no `userId`), `Http.TeamMemberView` and `Http.OrgRoleView` gain `id`, and `Http.CreateOrgRolePayload` is new.

- **Svelte** (`@thomasfosterau/effect-auth-svelte`): the form components and stores call the client, so they follow it with no change of their own.
- **SvelteKit** (`@thomasfosterau/effect-auth-sveltekit`): `credentialAction`, `credentialForm` and `credentialCommand` post a JSON:API document by default (`contentType` overrides it). Point `endpoint` at `…/sessions` for sign-in and `…/users` for sign-up, and build the body as a `sessions` or `users` document. A `202` is a `pending` result, never a redirect.
- **`Http.RemoteSession`** reads `GET /sessions/current?include=user`. Relay a credential post to `/sessions` (sign-in) or `/users` (sign-up), not to the old command routes.

## Checklist

1. Upgrade the auth service and every app that talks to it together.
2. Replace each old route your own code calls with the table above, and send `application/vnd.api+json` documents.
3. Read errors from the JSON:API error document (`errors[0].detail`, `errors[0].meta.code`) rather than `{ message }`.
4. Expect `201`, `202` and `204` where you checked for `200`.
5. If you implement `OrganizationStore`, add `getMemberById`, `getTeamMemberById` and `getOrgRoleById`, store the `TeamMember` and `OrgRole` ids, take `addTeamMember(record)`, and run `Testing.organizationStoreConformance()`.
6. Update calls to the client methods above that now take a record's own id.
7. Leave OAuth, OIDC, device-grant, registration, JWKS, SSO-callback and SCIM integrations as they are.
