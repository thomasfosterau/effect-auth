---
"@thomasfosterau/effect-auth": minor
---

**Security hardening (#718):** a record looked up by its id no longer reveals that it exists before the permission check. Before, an unknown id answered differently from another tenant's record, so a caller holding a foreign id could confirm it was real, and a stranger could learn whether an invitation was still pending.

- `PATCH` / `DELETE /organization-members/:id`, `GET /organization-members/:id/teams`, `DELETE /organization-domains/:id`, `POST /organization-domains/:id/verifications`, `PATCH` / `DELETE /organization-roles/:id` and `DELETE /team-members/:id` answer an unknown id with the same `403` and body as another tenant's record and a member without the permission: `Missing permission '<permission>' in this organization` (`member:update`, `member:delete`, `domain:manage`, `role:manage`, `team:manage-members`), or `You are not a member of this organization` for a membership's teams, which any member may read. An unknown id no longer answers `404`. The operator's `DELETE /admin/organization-domains/:id` still answers an unknown id `404`, after the admin check.
- The team operations (`updateTeam`, `deleteTeam`, `addTeamMember`, `removeTeamMember`, and so `PATCH` / `DELETE /teams/:id` and `POST /teams/:id/members`) refuse an unknown team with the `Missing permission` error a stranger gets, and `listTeamMembers` (`GET /teams/:id/members`) with the `You are not a member` one, instead of `Team not found`.
- `cancelInvitation` and `resendInvitation` (`PATCH /invitations/:id` to `canceled`, `POST /invitations/:id/deliveries`) check `invitation:cancel` / `invitation:create` first: an unknown id, a stranger and a member without the permission get the same `Missing permission` error and `403`, whatever the invitation's status, instead of `Invitation not found` or `Invitation is no longer pending`. A permitted member still gets `Invitation is no longer pending` for one that is not.

No public signature changes; the `404` and the `not found` messages these routes documented do.
