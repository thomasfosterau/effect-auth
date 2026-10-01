# ApiKey design

> **Revised in code.** API keys keep the `{ resource: actions[] }` map, but organization roles now
> use `"resource:action"` strings, so the two are checked separately (`ApiKey.ts`, `Permission.ts`).
> The text below is left as written.

`ApiKey` is a Primary Credential (ADR-0006), with the dual-ownership semantics of ADR-0010 — a
mandatory `userId` plus an optional `ownedByOrganizationId`. Six decisions shape it.

**Key structure: prefix-segment-body**, e.g. `ea_live_7zP4nXmK…`. The `ea_` prefix is
configurable per deployment (`acme_`, `proj_`, …) so deployers can register their own pattern with
secret-scanning tools (GitHub, gitleaks, TruffleHog). The middle segment (`live` / `test`)
distinguishes environments. The trade-off versus an opaque random body is one parse step at verify
time; the payoff is that leaked keys get detected by existing scanners. Worth it.

**Scopes reuse `PermissionStatement` from ADR-0009.** An ApiKey carries
`permissions: PermissionStatement`. The same `hasPermission` checks that work against a Member's
role work against an ApiKey holder — `OrganizationAccessControl` treats "what permissions does
this principal carry" as its input, not "who the principal is." Running a parallel scope system
inside ApiKey would force every deployer to learn two RBACs. Free-form scope strings remain
achievable by defining a role with the scope-as-resource and reading it that way.

**Ownership model follows Account.** `userId` mandatory, `ownedByOrganizationId` optional, dual
ownership cascades from ADR-0010 apply identically (User-delete revokes keys; Org-delete releases
keys to personal status). No special-casing for ApiKey.

**Expiry is optional, deployer-controlled.** `expiresAt?: Date` on the record; no library default.
Verification past expiry returns a structured error.

**Per-key rate-limit override is optional.** `rateLimit?: { maxRequests, windowMs }` lives on the
record; the existing `RateLimiter` is the consumer, keyed on the api-key id, falling back to a
global preset when null. No new rate-limit infrastructure.

**Operations surface stays small.** `createApiKey` (returns plaintext once + stored record),
`verifyApiKey(plaintext)`, `revokeApiKey(id)`, `listApiKeys({ userId, organizationId? })` (without
plaintext), `updateApiKey(id, partial)` for name/permissions/expiry. **No `regenerate`** — it's
just revoke + create from the consumer side, and one less verb in the API. A `lastUsedAt` field
is updated on each successful verify, best-effort and asynchronous (verification doesn't block on
the write).

The trade-off cluster: structured keys, statement-shaped permissions, and dual ownership all
inherit from existing decisions. The one fresh choice is no `regenerate` op — a convenience some
consumers expect — which we accept in exchange for a smaller, more honest verb set.
