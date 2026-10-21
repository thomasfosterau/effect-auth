---
"@thomasfosterau/effect-auth": minor
"@thomasfosterau/effect-auth-client": minor
---

Organizations: member deactivation, verified domains, JIT provisioning, invitation resend, and a per-organization default role.

- **Member status.** `Member.status` (`"active" | "inactive"`, absent means active) with
  `deactivateMember` / `reactivateMember` (`member:update`, `POST
  /organization/:organizationId/members/:userId/{deactivate,reactivate}`). An inactive member keeps
  its row, its team memberships and its role — parked in `previousRole` while the row is demoted to
  the organization's default role — and is treated as a non-member by every permission check,
  including the `OrganizationEntities` policy projection. Only an owner may deactivate an owner, and
  the last _active_ owner may not be deactivated or demoted. **Deliberate deviation from WorkOS:**
  application sessions are _not_ revoked, because a session is app-scoped while a membership is
  organization-scoped — signing a user out of every tenant because one deactivated them is the wrong
  default for a multi-tenant app. The new `onMemberDeactivated` config hook is where an app that
  wants WorkOS's behavior calls `invalidateUserSessions`.
- **Organization domains.** New `OrganizationDomain` record and `OrganizationDomainStore` contract
  (43 store contracts now; `memoryOrganizationDomainStore` included), plus list/add/remove/verify
  endpoints under `/organization/:organizationId/domains`. Domains are globally unique — pending
  claims included, so verification order can never decide which tenant wins — writes need the new
  `domain:manage` permission (granted to `owner` and `admin` in `defaultOrganizationRoles`), and any
  member may list. DNS verification adds no dependency: implement the new `DomainVerifier` contract
  over your own resolver, or claim domains with the `"manual"` strategy and attest them through the
  verify endpoint. The DNS TXT token is generated server-side.
- **JIT provisioning on SSO sign-in.** Opt-in per organization via `Organization.jitProvisioning`
  (default `false` — silent domain absorption is a consent surprise). After the shared SSO
  provisioning tail resolves the user, a verified email whose domain is a _verified_ claim of a
  JIT-enabled organization adds an active membership with that organization's default role. Failures
  are logged and swallowed: membership is fail-open, authentication never is.
- **`resendInvitation`.** Same row and id, `expiresAt` pushed out by the configured TTL, delivery
  callback fired again; gated on `invitation:create` like inviting, and refused for unknown,
  accepted, rejected or canceled invitations. `POST /invitations/:invitationId/resend`.
- **Per-organization default role.** `Organization.defaultRole` (default `"member"`), settable only
  by owners (`role:manage`, `PUT /organization/:organizationId/default-role`) and validated against
  the organization's role set. Used wherever a member is added without an explicit role: `addMember`
  (its `role` argument and the `AddMemberPayload` field are now optional), JIT provisioning, the SCIM
  provisioning path, and SSO first-login provisioning — the `ScimConfig.defaultRole` /
  `SsoConfig.defaultRole` options still win when set.

The client gains `organization.{deactivateMember,reactivateMember,setDefaultRole,resendInvitation,listDomains,addDomain,verifyDomain,removeDomain}`;
`OrganizationView` now carries `defaultRole` and `jitProvisioning`, and `MemberView` carries `status`
and `previousRole`.
