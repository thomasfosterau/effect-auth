---
"@thomasfosterau/effect-auth": minor
---

Add the operator's domain lookup, and show who attested a domain claim only to platform admins.

- `GET /admin/organization-domains?filter[domain]=` (admin-gated, as the attestation and release are) answers every organization's claim on a domain, in any state, oldest first, so a dispute can find the claim id to release. It is `OrganizationService.listDomainClaims(domain)` on the server and `client.admin.lookupDomain(domain)` in the browser client. A missing or invalid domain answers `400`.
- **Breaking:** `OrganizationDomainStore` gains a required `listByDomain(domain)` (every claim on a normalized domain, oldest first). `memoryOrganizationDomainStore` implements it; a custom store must add it.
- **Breaking:** tenant reads of `organization-domains` (`GET /organizations/:id/domains`, `POST /organizations/:id/domains`, `POST /organization-domains/:id/verifications`) no longer carry the `attester` relationship, and the client's `organization.listDomains`, `addDomain` and `verifyDomain` no longer answer `attestedBy`. Only the platform-admin endpoints answer it, as the new `Http.Resources.OperatorOrganizationDomain` view; `Http.Resources.OrganizationDomain` is now the tenant's view, without `attester`.
