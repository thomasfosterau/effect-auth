---
"@thomasfosterau/effect-auth": minor
---

**Security fix (#715):** an organization's invitation list is readable only by a member whose role carries `invitation:create`, the permission that issues invitations. Before, any signed-in user who knew an organization id could list every invitation it had sent (invitee emails, roles and inviters) through `GET /organizations/:id/invitations`.

- `GET /organizations/:id/invitations` answers `403` to a non-member, to a member without `invitation:create` and to an unknown organization id alike, with the same body, so the answer reveals no ids. The browser client's `organization.listInvitations(organizationId)` is unchanged.

**Breaking:**

- `OrganizationService.listInvitations(organizationId)` is now `listInvitations(actorId, organizationId)` and can fail with an `OrganizationError`.
- `OrganizationService.acceptInvitation` answers `AcceptedInvitation` (`{ member, invitation }`: the new membership and the invitation as accepted) instead of the bare `Member`, since the invitee can no longer read the invitation through `listInvitations`. Read `.member` where you read the result before.
