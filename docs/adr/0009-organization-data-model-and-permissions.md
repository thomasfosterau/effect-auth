# Organization data model and Statement-based permissions

> **Revised in code.** Roles are no longer global-only: an organization can replace a configured
> role with its own `OrgRole` at runtime, and organization permissions are `"resource:action"`
> strings rather than a `PermissionStatement`. The active organization is
> `session.attributes.activeOrganizationId`, not an `ActiveOrgSelection` entity. Teams shipped
> ([ADR-0016](0016-hierarchical-teams.md)). See `Organization.ts` and
> [docs/CONTEXT.md](../CONTEXT.md). The text below is left as written.

Three entities ship initially: `Organization`, `Member` (the User-to-Organization relationship
with a `role: string`), and `Invitation`. Teams are deferred. A separate
`ActiveOrgSelection { sessionId, organizationId }` entity tracks the currently-active org per
Session by default; an `activeOrgStrategy: "session-attribute"` config flag switches to storing
the pointer on `Session.attributes` for deployments that prefer that shape — both backings live
behind one `ActiveOrgService` whose `Layer` the consumer picks.

Roles are configured globally on the `OrganizationService`, not stored per-Organization. Each
`RoleDefinition` has a name and a `PermissionStatement` — a `Record<resource, readonly action[]>`
mapping resources to allowed actions, matching better-auth's shape. The `OrganizationAccessControl`
service provides `hasPermission`/`requirePermission` checks keyed by `(orgId, userId, required)`,
and an intersection check (does the member's role include all the required permissions?). We
explicitly do **not** ship per-org role overrides initially; storage-backed role definitions are
error-prone (drift, migration friction), and the better-auth feature can be added later if real
demand appears.

One role name is reserved: `"owner"`. Its default `PermissionStatement` is wildcard (every action
on every resource), but deployers can narrow it (e.g. "owners can't bypass audit logging"). The
reserved name anchors the **sole-owner rule**: an Organization always has at least one Member
with role `"owner"`. Operations that would violate this — `removeMember`, `updateMemberRole`,
`transferOwnership`, `deleteUser` for a sole-owner — return a structured error. The rule mirrors
`preventLastCredentialUnlink` from ADR-0007 (same defensive posture, different domain).

Invitations are `Verification` entities (ADR-0006), hashed at rest (ADR-0004), with extra fields
`organizationId`, `invitedEmail`, `proposedRole`, `inviterUserId`. Two acceptance paths are
first-class: `acceptInvitationAsExistingUser(token, userId)` for users who already have an
account, and `acceptInvitationAsNewUser(token, signUpData)` for invitation-to-signup. Both consume
the invitation row on success and create the `Member` row.

The trade-off: a Statement-based permission system is more surface area than free-form role
strings, and ships before any consumer has demanded per-org overrides. We accept this because the
existing `AuthorizationPolicy`/`RoleStore` is already statement-flavoured (resource/action
pairs), the structure mirrors better-auth so deployments migrating from it find a familiar shape,
and the alternative — free-form roles with no library checks — punts every permission decision to
the consumer with zero library support.
