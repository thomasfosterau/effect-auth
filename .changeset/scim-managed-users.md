---
"@thomasfosterau/effect-auth": minor
---

SCIM now writes only to users the connection's organization manages, and only to addresses on its verified domains. A connection still reads and lists every member, but changing `userName`, `emails`, `displayName` or `externalId` needs the organization to manage the user (it created them through SCIM or SSO, or their primary email is on one of its verified domains); otherwise the answer is `400 mutability`. Every address SCIM claims must be on a verified domain (`400 invalidValue`, nothing written), and an address off them is never unclaimed. `active: false` or `DELETE /Users/:id` on a member the organization does not manage deactivates only the membership, not the account. Users SCIM creates carry the `provisionedBy` stamp.

Breaking: provide an `OrganizationDomainStore` and verify the organization's domains before upgrading, or SCIM refuses to create users.
