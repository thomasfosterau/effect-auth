---
"@thomasfosterau/effect-auth": minor
---

Organization membership and invitations can no longer be used against other users.

- `addMember` (and `POST /organizations/:id/members`) adds only a user the organization manages, as `Auth.ManagedUser.isManagedUser` decides; an unknown user id is refused alike, and anyone else joins by invitation. `OrganizationService.layer` now requires `UserStore`.
- `leaveOrganization(userId, organizationId)` lets a member leave without `member:delete`; over HTTP, `DELETE /organization-members/:id` of your own membership leaves. The last active owner cannot leave.
- `organizationLimit` counts only organizations the user owns or joined by accepting an invitation, not memberships someone else made for them.
- `pendingInvitationLimit` (default 100) caps pending, unexpired invitations per organization, and `invitationResendCooldown` (default 60 seconds, `0` turns it off) spaces invitation emails from one organization to one address, across a cancel and re-invite too. A send inside the cooldown fails with `ResendTooSoonError`, which `POST /organizations/:id/invitations` and `POST /invitations/:id/deliveries` answer with `429`. `Invitation` gains an optional `sentAt`.
- Accepting an invitation re-checks that its inviter still holds `invitation:create` and every permission of its role. A resend requires the resender to be able to grant the role, and makes them the inviter.

Breaking: wire a `UserStore` into `OrganizationService.layer`, and stamp or verify-domain the users you add directly (or invite them instead).
