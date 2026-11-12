---
"@thomasfosterau/effect-auth": minor
---

**Security — an organization can no longer self-attest an email domain, and a domain claim no longer reveals or blocks another tenant's (#598).** Any user could create an organization, claim someone else's domain with the `manual` strategy and call `verifyDomain`: holding `domain:manage` was the whole attestation. The claim was then `verified`, so with `jitProvisioning` on, every SSO user at that domain joined the attacker's organization. Because claims were globally unique, the real owner could never claim the domain, and the refusal ("already claimed by another organization") confirmed other tenants' claims.

Now a tenant proves a domain only through DNS, and manual attestation is the application operator's:

- `OrganizationService.addDomain` always makes a `dns` claim with a server-minted token. `AddOrganizationDomainInput` loses `verificationStrategy`, and over HTTP `POST /organizations/:id/domains` answers `400` to `verificationStrategy: "manual"` (`"dns"` is still accepted). The `organization-domains` resource's `createInput` no longer has the attribute.
- `verifyDomain` runs only the `DomainVerifier` check. It refuses an unverified `manual` claim, and a passed check while another organization holds the domain verified.
- New `OrganizationService.attestDomain(organizationId, domain)`: a server-side call, with no actor, that the operator makes after checking ownership out of band. It attests the organization's existing claim in place (same id, DNS token dropped) or creates one, `verified` with the `manual` strategy. The platform-admin endpoint is `POST /admin/organization-domains` (the domain as an attribute, the organization as the `organization` relationship), gated on the server's `isAdmin` like SSO connection registration, never on an organization permission: `201` with the claim, `400` on a refusal. The browser client gains `admin.attestDomain({ organizationId, domain })`, typed with the new `Http.AdminAttestDomainPayload`.
- Claims are unique per organization and domain, not globally. Several organizations may hold pending claims on one domain, each with its own token, and at most one claim per domain is `verified`. `addDomain` consults only the organization's own claims, so it no longer reveals another tenant's claim, and a pending claim cannot squat a domain.
- **Store contract:** `OrganizationDomainStore.getByDomain` is replaced by `getVerifiedByDomain(domain)`, which answers only the `verified` claim on the domain (or `null`). JIT provisioning reads it.

Migration:

- Replace `getByDomain` in your `OrganizationDomainStore` with `getVerifiedByDomain`, filtering on `verificationState = 'verified'`. Replace a unique index on `domain` with one on `(organization_id, domain)`, plus, where your database has partial indexes, a unique index on `domain` over the verified rows.
- Drop `verificationStrategy` from `addDomain` calls. A tenant that cannot publish a DNS record asks the operator, who calls `attestDomain` (or `POST /admin/organization-domains`).
- Review the claims already `verified` with the `manual` strategy: before this release any organization admin could have made one. Delete those whose ownership you can't confirm out of band. A `manual` claim still `pending` can no longer be verified by the organization: release it and claim the domain for DNS verification, or attest it as the operator.
