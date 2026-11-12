---
"@thomasfosterau/effect-auth": minor
---

List the signed-in user's own pending invitations (#706). `OrganizationService.listInvitationsForUser(userId)` answers the pending, unexpired invitations addressed to the user's verified email identifiers (the ones they may accept or reject by id without the emailed token, #673); an unverified address contributes none. The HTTP tier serves it as `GET /invitations`, the top-level `invitations` collection scoped to the caller (`401` without a session), whose resources never carry the token or its digest, and the browser client as `client.organization.listMyInvitations()`.
