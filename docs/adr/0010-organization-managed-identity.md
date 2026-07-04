# Organization-managed identity (User and Account ownership)

Both `User` and `Account` carry an optional `ownedByOrganizationId` field. Each level of ownership
confers admin rights scoped to what's owned: User-level lets an Organization delete, suspend,
force-update the User, transitively manage any Account on the User, and force-release ownership.
Account-level lets an Organization revoke, force-update, or force-release only that Account; it
cannot touch the User itself.

The two ownerships are independent and may coexist on the same User. If Org A owns a User and
Org B owns one of that User's Accounts, both orgs have rights over that Account — Org A's via
transitive User-ownership, Org B's directly — and neither blocks the other. Each
`ownedByOrganizationId` is a single nullable column, so two orgs co-owning the same entity is
disallowed at the schema level.

Cascades on delete:

- Deleting a User revokes every Account on the User regardless of who owned each Account — the
  Account row is gone, so any Org-B Account claim disappears with it.
- Deleting an Organization that owned a User releases that User to personal status. Accounts on
  the User that another org owned remain that org's. The User can end up personal-but-with-an-
  org-owned-Account, which is a coherent state.
- Deleting an Organization that owned only an Account releases that Account; the User is
  unaffected.

An owned User is automatically a `Member` of its owning Organization. Removing that Membership is
equivalent to releasing ownership — they're two views of the same relationship. Account-only
ownership does **not** create a Membership — it's a managed credential, not a workspace
relationship; the User may or may not be a Member of the Account's owning Org.

Users cannot unilaterally release themselves from User-ownership by default. An
`allowUserSelfRelease: boolean` config opens that escape hatch for deployments that want it. The
`preventLastCredentialUnlink` rule from ADR-0007 still applies for personal Users; for owned
Users, the owning Org can override it (intentional deprovisioning leaves the User credential-less,
because deprovisioning is the point).

The trade-off: dual ownership doubles the surface area compared to either level alone, introduces
the unusual A-owns-User-B-owns-Account case, and requires the precedence/cascade rules to be
spelled out (above). We accept this because the two patterns cover materially different
scenarios — workspace-owned identity (the SaaS-tenant model) vs. SCIM-provisioned credentials on
otherwise-personal Users (the enterprise-managed-credential model) — and collapsing to one level
would force one pattern into an awkward approximation of the other.
