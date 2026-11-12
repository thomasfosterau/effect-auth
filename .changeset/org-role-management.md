---
"@thomasfosterau/effect-auth": minor
---

Organization role management follows the grant rule, and invitations can be answered in-app (#673).

- **The default `owner` role is `"*:*"`** (`defaultOrganizationRoles.owner`), so an owner can grant, define and delete any custom role, application permissions (`posts:write`) and wildcards (`team:*`) included. It stays protected from redefinition. An app that passes its own `roles` map keeps its owner entry as written.
- **`upsertOrgRole` and `deleteOrgRole` follow #585's grant rule.** Defining or redefining a role needs the actor's role to carry every permission in the new definition and every permission the name resolves to now (its custom definition, else its static `config.roles` entry); deleting one needs every permission the definition held and every permission of the static entry it falls back to. An actor can no longer redefine or delete their own role, so a custom role holding `role:manage` cannot widen itself. Over HTTP each refusal answers `403`, as the other role-management refusals do.
- **A verified address answers an invitation by id.** `InvitationResponseInput.token` (and so `acceptInvitation` / `rejectInvitation`'s input) is now optional: a signed-in user whose matching email identifier is verified may accept or reject without the emailed token, so a dashboard "pending invitations" list works. An unverified match is refused without the token and still accepts with it, the token being the address's first proof (#586); a user the invitation is not addressed to gets "Invitation not found". `PATCH /invitations/:id` no longer answers `400` for a missing `token` attribute, and the browser client's `organization.acceptInvitation(id, token?)` / `rejectInvitation(id, token?)` take the token optionally.
