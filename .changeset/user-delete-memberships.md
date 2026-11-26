---
"@thomasfosterau/effect-auth": minor
---

Deleting a user deletes their organization memberships, and never leaves an organization without an owner.

- Every path that deletes a user (`AdminService.removeUser`, `AccountManagementService.confirmAccountDeletion`, `AnonymousService.linkAccount`, `UserService.deleteUser` and `AccountDeletion.deleteUser`) now deletes the user's organization and team memberships, when an `OrganizationStore` is in the context, before the identifiers and the user row.
- **Breaking:** a user who is the last active owner of an organization that still has other members is refused with the new `LastOrganizationOwnerError` (code `LAST_ORGANIZATION_OWNER`), naming the organization, before anything is deleted; `confirmAccountDeletion` and `linkAccount` check it before their app callbacks. Each of those methods' error channels gains it, and `DELETE /admin/users/:id` and `POST /account-deletions/redemptions` answer it with `409`.
- The new `OrganizationOwnerRole` reference (default `owner`) names the owner role the purge checks; `OrganizationService` uses it as `creatorRole`'s default. An app with a custom owner role provides the reference.
