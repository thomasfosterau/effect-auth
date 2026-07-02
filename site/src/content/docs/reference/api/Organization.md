---
title: "Organization"
description: "API reference for the Organization module."
---

## Organization overview

Organizations (multi-tenant teams) for effect-auth.

Mirrors better-auth's organization plugin: users create organizations,
invite members by email, and manage member roles. Every mutating operation
is permission-checked against a configurable role → permission map using
`"resource:action"` permission strings.

**Active organization:** this module deliberately does not manage a
per-session "active organization" (better-auth's `setActiveOrganization`).
The conventional integration is to store the selected organization id on
the session's attribute bag - e.g.
`sessionManager.createSession(userId, { activeOrganizationId: org.id })`
or by updating `session.attributes.activeOrganizationId` through your
session store - and read it back from `session.attributes` when handling
requests.

---

<h2 class="text-delta">Table of contents</h2>

- [utils](#utils)
  - [CreateOrganizationInput (interface)](#createorganizationinput-interface)
  - [FullOrganization (interface)](#fullorganization-interface)
  - [Invitation (interface)](#invitation-interface)
  - [InvitationStatus (type alias)](#invitationstatus-type-alias)
  - [InviteMemberInput (interface)](#invitememberinput-interface)
  - [Member (interface)](#member-interface)
  - [Organization (interface)](#organization-interface)
  - [OrganizationConfig (interface)](#organizationconfig-interface)
  - [OrganizationError (class)](#organizationerror-class)
  - [OrganizationService](#organizationservice)
  - [OrganizationService (interface)](#organizationservice-interface)
  - [OrganizationServiceLayer](#organizationservicelayer)
  - [OrganizationServiceTag (class)](#organizationservicetag-class)
  - [OrganizationStore](#organizationstore)
  - [OrganizationStore (interface)](#organizationstore-interface)
  - [OrganizationStoreTag (class)](#organizationstoretag-class)
  - [UpdateOrganizationInput (interface)](#updateorganizationinput-interface)
  - [defaultOrganizationRoles](#defaultorganizationroles)
  - [makeOrganizationService](#makeorganizationservice)

---

# utils

## CreateOrganizationInput (interface)

Input for creating an organization

**Signature**

```ts
export interface CreateOrganizationInput {
  readonly name: string;
  readonly slug: string;
  readonly logo?: string;
  readonly metadata?: Record<string, unknown>;
}
```

## FullOrganization (interface)

An organization together with its member list

**Signature**

```ts
export interface FullOrganization {
  readonly organization: Organization;
  readonly members: ReadonlyArray<Member>;
}
```

## Invitation (interface)

An email invitation to join an organization.

**Signature**

```ts
export interface Invitation {
  readonly id: string;
  readonly organizationId: string;
  /** Normalized (trimmed, lowercased) invitee email */
  readonly email: string;
  /** Role the invitee receives upon acceptance */
  readonly role: string;
  readonly status: InvitationStatus;
  /** User id of the member who created the invitation */
  readonly inviterId: string;
  /** Epoch milliseconds */
  readonly expiresAt: number;
  /** Epoch milliseconds */
  readonly createdAt: number;
}
```

## InvitationStatus (type alias)

Lifecycle states of an invitation.

**Signature**

```ts
export type InvitationStatus = "pending" | "accepted" | "rejected" | "canceled";
```

## InviteMemberInput (interface)

Input for inviting a member by email

**Signature**

```ts
export interface InviteMemberInput {
  readonly email: string;
  readonly role: string;
}
```

## Member (interface)

A user's membership in an organization.

**Signature**

```ts
export interface Member {
  readonly id: string;
  readonly organizationId: string;
  readonly userId: string;
  /** Role name, resolved against the configured role → permission map */
  readonly role: string;
  /** Epoch milliseconds */
  readonly createdAt: number;
}
```

## Organization (interface)

An organization (team / tenant).

**Signature**

```ts
export interface Organization {
  readonly id: string;
  readonly name: string;
  /** URL-friendly unique identifier */
  readonly slug: string;
  readonly logo?: string;
  /** Arbitrary app-specific metadata */
  readonly metadata: Record<string, unknown>;
  /** Epoch milliseconds */
  readonly createdAt: number;
}
```

## OrganizationConfig (interface)

Organization service configuration

**Signature**

```ts
export interface OrganizationConfig {
  /** Whether users may create organizations at all (default: true) */
  readonly allowUserToCreateOrganization?: boolean;
  /** Maximum number of organizations a user may belong to (default: 5) */
  readonly organizationLimit?: number;
  /** Maximum number of members per organization (default: 100) */
  readonly membershipLimit?: number;
  /** Invitation lifetime in milliseconds (default: 48 hours) */
  readonly invitationExpiresIn?: number;
  /** Role assigned to the creator of an organization (default: "owner").
   * This role is also treated as the protected "owner" role for the
   * last-owner safeguards in `removeMember`/`updateMemberRole`. */
  readonly creatorRole?: string;
  /** Role → permission map (default: {@link defaultOrganizationRoles}) */
  readonly roles?: Record<string, ReadonlyArray<string>>;
  /** Optional invitation email delivery */
  readonly sendInvitationEmail?: (
    invitation: Invitation,
    organization: Organization,
  ) => Effect.Effect<void, OrganizationError>;
}
```

## OrganizationError (class)

Organization error

**Signature**

```ts
export declare class OrganizationError
```

## OrganizationService

**Signature**

```ts
export declare const OrganizationService: typeof OrganizationServiceTag;
```

## OrganizationService (interface)

Organization service

**Signature**

```ts
export interface OrganizationService {
  /**
   * Create an organization. Enforces `allowUserToCreateOrganization`,
   * `organizationLimit` (organizations the user already belongs to) and slug
   * uniqueness. The creator becomes a member with `creatorRole`.
   */
  readonly createOrganization: (
    userId: string,
    input: CreateOrganizationInput,
  ) => Effect.Effect<Organization, OrganizationError | Errors.AuthError, OrganizationStoreTag>;

  /**
   * Update an organization's fields. Requires the `organization:update`
   * permission. Slug changes are checked for uniqueness.
   */
  readonly updateOrganization: (
    userId: string,
    organizationId: string,
    updates: UpdateOrganizationInput,
  ) => Effect.Effect<Organization, OrganizationError | Errors.AuthError, OrganizationStoreTag>;

  /**
   * Delete an organization. Requires the `organization:delete` permission.
   */
  readonly deleteOrganization: (
    userId: string,
    organizationId: string,
  ) => Effect.Effect<void, OrganizationError | Errors.AuthError, OrganizationStoreTag>;

  /**
   * Fetch an organization together with all of its members.
   */
  readonly getFullOrganization: (
    organizationId: string,
  ) => Effect.Effect<FullOrganization, OrganizationError | Errors.AuthError, OrganizationStoreTag>;

  /**
   * List the organizations a user belongs to.
   */
  readonly listOrganizations: (
    userId: string,
  ) => Effect.Effect<ReadonlyArray<Organization>, Errors.AuthError, OrganizationStoreTag>;

  /**
   * Invite a user (by email) to the organization. Requires the
   * `invitation:create` permission. Rejects duplicate pending invitations for
   * the same email + organization and enforces `membershipLimit`. When
   * `sendInvitationEmail` is configured it is invoked with the created
   * invitation.
   */
  readonly inviteMember: (
    inviterId: string,
    organizationId: string,
    input: InviteMemberInput,
  ) => Effect.Effect<Invitation, OrganizationError | Errors.AuthError, OrganizationStoreTag>;

  /**
   * Accept a pending invitation. Validates that the invitation is pending,
   * unexpired, and addressed to `userEmail`. Creates the membership and marks
   * the invitation accepted.
   */
  readonly acceptInvitation: (
    userId: string,
    invitationId: string,
    userEmail: string,
  ) => Effect.Effect<Member, OrganizationError | Errors.AuthError, OrganizationStoreTag>;

  /**
   * Reject a pending invitation addressed to `userEmail`.
   */
  readonly rejectInvitation: (
    invitationId: string,
    userEmail: string,
  ) => Effect.Effect<Invitation, OrganizationError | Errors.AuthError, OrganizationStoreTag>;

  /**
   * Cancel a pending invitation. The canceler needs the `invitation:cancel`
   * permission in the invitation's organization.
   */
  readonly cancelInvitation: (
    cancelerId: string,
    invitationId: string,
  ) => Effect.Effect<Invitation, OrganizationError | Errors.AuthError, OrganizationStoreTag>;

  /**
   * List all invitations for an organization (any status).
   */
  readonly listInvitations: (
    organizationId: string,
  ) => Effect.Effect<ReadonlyArray<Invitation>, Errors.AuthError, OrganizationStoreTag>;

  /**
   * List pending, unexpired invitations addressed to an email.
   */
  readonly listUserInvitations: (
    email: string,
  ) => Effect.Effect<ReadonlyArray<Invitation>, Errors.AuthError, OrganizationStoreTag>;

  /**
   * Add a user to the organization directly (no invitation). Requires the
   * `member:create` permission and enforces `membershipLimit`.
   */
  readonly addMember: (
    actorId: string,
    organizationId: string,
    userId: string,
    role: string,
  ) => Effect.Effect<Member, OrganizationError | Errors.AuthError, OrganizationStoreTag>;

  /**
   * Remove a member. Requires the `member:delete` permission. An owner can
   * only be removed by another owner, and the last owner can never be removed.
   */
  readonly removeMember: (
    actorId: string,
    organizationId: string,
    memberUserId: string,
  ) => Effect.Effect<void, OrganizationError | Errors.AuthError, OrganizationStoreTag>;

  /**
   * Change a member's role. Requires the `member:update` permission. The last
   * owner cannot be demoted.
   */
  readonly updateMemberRole: (
    actorId: string,
    organizationId: string,
    memberUserId: string,
    role: string,
  ) => Effect.Effect<Member, OrganizationError | Errors.AuthError, OrganizationStoreTag>;

  /**
   * Whether the user's role in the organization grants the given
   * `"resource:action"` permission. Non-members simply get `false`.
   */
  readonly checkPermission: (
    userId: string,
    organizationId: string,
    permission: string,
  ) => Effect.Effect<boolean, Errors.AuthError, OrganizationStoreTag>;

  /**
   * Like {@link checkPermission} but fails with `OrganizationError` when the
   * permission is not granted.
   */
  readonly requirePermission: (
    userId: string,
    organizationId: string,
    permission: string,
  ) => Effect.Effect<void, OrganizationError | Errors.AuthError, OrganizationStoreTag>;
}
```

## OrganizationServiceLayer

**Signature**

```ts
export declare const OrganizationServiceLayer: (
  config?: OrganizationConfig,
) => Layer.Layer<OrganizationServiceTag, never, never>;
```

## OrganizationServiceTag (class)

**Signature**

```ts
export declare class OrganizationServiceTag
```

## OrganizationStore

**Signature**

```ts
export declare const OrganizationStore: typeof OrganizationStoreTag;
```

## OrganizationStore (interface)

Storage interface for organizations, members, and invitations.
Implement with your preferred backend (SQL, Redis, ...).

Note: `deleteOrganization` should cascade - implementations are expected
to remove the organization's members and invitations as well.

**Signature**

```ts
export interface OrganizationStore {
  readonly createOrganization: (
    organization: Organization,
  ) => Effect.Effect<Organization, Errors.AuthError>;
  readonly getOrganizationById: (
    organizationId: string,
  ) => Effect.Effect<Organization | null, Errors.AuthError>;
  readonly getOrganizationBySlug: (
    slug: string,
  ) => Effect.Effect<Organization | null, Errors.AuthError>;
  readonly updateOrganization: (
    organization: Organization,
  ) => Effect.Effect<Organization, Errors.AuthError>;
  readonly deleteOrganization: (organizationId: string) => Effect.Effect<void, Errors.AuthError>;

  readonly createMember: (member: Member) => Effect.Effect<Member, Errors.AuthError>;
  readonly getMember: (
    organizationId: string,
    userId: string,
  ) => Effect.Effect<Member | null, Errors.AuthError>;
  readonly updateMember: (member: Member) => Effect.Effect<Member, Errors.AuthError>;
  readonly deleteMember: (memberId: string) => Effect.Effect<void, Errors.AuthError>;
  readonly listMembersByOrganization: (
    organizationId: string,
  ) => Effect.Effect<ReadonlyArray<Member>, Errors.AuthError>;
  readonly listMembersByUser: (
    userId: string,
  ) => Effect.Effect<ReadonlyArray<Member>, Errors.AuthError>;
  readonly countMembersByOrganization: (
    organizationId: string,
  ) => Effect.Effect<number, Errors.AuthError>;

  readonly createInvitation: (
    invitation: Invitation,
  ) => Effect.Effect<Invitation, Errors.AuthError>;
  readonly getInvitation: (
    invitationId: string,
  ) => Effect.Effect<Invitation | null, Errors.AuthError>;
  readonly updateInvitation: (
    invitation: Invitation,
  ) => Effect.Effect<Invitation, Errors.AuthError>;
  readonly listInvitationsByOrganization: (
    organizationId: string,
  ) => Effect.Effect<ReadonlyArray<Invitation>, Errors.AuthError>;
  readonly listInvitationsByEmail: (
    email: string,
  ) => Effect.Effect<ReadonlyArray<Invitation>, Errors.AuthError>;
}
```

## OrganizationStoreTag (class)

**Signature**

```ts
export declare class OrganizationStoreTag
```

## UpdateOrganizationInput (interface)

Partial update of an organization's fields

**Signature**

```ts
export interface UpdateOrganizationInput {
  readonly name?: string;
  readonly slug?: string;
  readonly logo?: string;
  readonly metadata?: Record<string, unknown>;
}
```

## defaultOrganizationRoles

Default role → permission map, mirroring better-auth's built-in
organization roles. Permissions are `"resource:action"` strings.

- `owner` - full control (organization update/delete, member and
  invitation management)
- `admin` - member and invitation management plus organization updates,
  but cannot delete the organization
- `member` - read-only participant (no management permissions)

Override via {@link OrganizationConfig.roles}.

**Signature**

```ts
export declare const defaultOrganizationRoles: Record<string, readonly string[]>;
```

## makeOrganizationService

Create an organization service

**Signature**

```ts
export declare const makeOrganizationService: (
  config?: OrganizationConfig,
) => Effect.Effect<OrganizationService, never>;
```
