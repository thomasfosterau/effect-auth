---
"@thomasfosterau/effect-auth": minor
---

**Security fix (#717):** an organization and its member list are readable only by an active member. Before, any signed-in user who knew an organization id could read the organization and every membership in it (user ids, roles, statuses) through `GET /organizations/:id` and `GET /organizations/:id/members`, and the `404` an unknown id got confirmed which ids exist.

- `GET /organizations/:id` and `GET /organizations/:id/members` answer `403` to a non-member, to a deactivated member and to an unknown organization id alike, with the same body, as `GET /organizations/:id/teams`, `/domains` and `/roles` already did. An unknown id no longer answers `404`. The browser client's `organization.get(organizationId)` is unchanged and rejects with that `403`.

- `OrganizationService.listOrganizations(userId)` (and so `GET /organizations`) lists only the organizations the user is an _active_ member of: a deactivated membership no longer shows its organization, since its holder can no longer read it.

**Breaking:**

- `OrganizationService.getFullOrganization(organizationId)` is now `getFullOrganization(actorId, organizationId)`. It requires the actor's active membership and fails with an `OrganizationError` for a non-member and for an organization that does not exist alike.
