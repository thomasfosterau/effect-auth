---
"@thomasfosterau/effect-auth": minor
---

**Breaking (HTTP, store contract, client):** organizations, members, invitations and device sessions are JSON:API resources (#205, slice 4a). The endpoints take `application/vnd.api+json` documents and answer JSON:API documents and error documents.

| Before                                                                          | Now                                                                                                                                   |
| ------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------- |
| `GET /multi-session/list`                                                       | `GET /device-sessions`: `device-sessions` resources (`active` marks the current one), their users in `included`                       |
| `POST /multi-session/set-active`                                                | `PATCH /device-sessions/active` with a `device-sessions` linkage: `204`                                                               |
| `POST /multi-session/revoke`                                                    | `DELETE /device-sessions/:id`: `204`                                                                                                  |
| `GET /organizations` · `POST /organization/create`                              | `GET /organizations` · `POST /organizations` (`201`)                                                                                  |
| `GET` · `PATCH` · `DELETE /organization/:organizationId`                        | `GET` · `PATCH` · `DELETE /organizations/:id`; `GET` answers the organization alone, its members are `GET /organizations/:id/members` |
| `PUT /organization/:organizationId/default-role`                                | `PATCH /organizations/:id` with `defaultRole`                                                                                         |
| `POST /organization/set-active`                                                 | `PATCH /organizations/active` with an `organizations` linkage, or `data: null` to clear it: `204`                                     |
| `POST /organization/:organizationId/members`                                    | `POST /organizations/:id/members`, the user as the `user` relationship: `201`                                                         |
| `PATCH /organization/:organizationId/members` (by `userId`)                     | `PATCH /organization-members/:id` with `role`                                                                                         |
| `POST /organization/:organizationId/members/:userId/deactivate` · `/reactivate` | `PATCH /organization-members/:id` with `status: "inactive"` · `"active"`                                                              |
| `DELETE /organization/:organizationId/members/:userId`                          | `DELETE /organization-members/:id`: `204`                                                                                             |
| `GET` · `POST /organization/:organizationId/invitations`                        | `GET` · `POST /organizations/:id/invitations` (`201`)                                                                                 |
| `POST /invitations/:invitationId/accept` · `/reject` · `/cancel`                | `PATCH /invitations/:id` with `status` `accepted` (the new membership in `meta.membership`) · `rejected` · `canceled`                 |
| `POST /invitations/:invitationId/resend`                                        | `POST /invitations/:id/deliveries`: `202` with the invitation                                                                         |

- **Store contract:** `OrganizationStore` gains `getMemberById(memberId)`, answering the membership with that `Member.id` (in any organization) or `null`. A membership is now addressed by its stored id, so every `OrganizationStore` implementation must add it; `Testing.organizationStoreConformance()` (`@thomasfosterau/effect-auth/testing`) checks it with the rest of the membership contract. `OrganizationService` gains `getMemberById` as well.
- **Device sessions are named by their stored id** (the hash of the session token), never the token: the old `/multi-session/*` list answered, and its actions took, the raw tokens the device's cookies hold. A device-session id is safe in a URL.
- `PATCH /organizations/:id` now applies `jitProvisioning` (the old endpoint accepted and dropped it).
- `Http.UpdateMemberRolePayload` is `{ role }` (no `userId`).
- `./client`: `organization.updateMemberRole(memberId, { role })`, `removeMember(memberId)`, `deactivateMember(memberId)` and `reactivateMember(memberId)` take the membership's own `id` (from `get(…).members` or `addMember`) instead of `(organizationId, userId)`. `multiSession.setActive` / `revoke` take the `session.id` that `multiSession.list()` answers, now the stored id. The other organization and multi-session methods keep their arguments and results and call the new endpoints.
- Every old endpoint, store-contract, client and status-code change of the conversion is in [the migration guide](https://github.com/thomasfosterau/effect-auth/blob/trunk/docs/guides/jsonapi-migration.md).
