---
"@thomasfosterau/effect-auth": minor
---

List operations no longer load the whole directory. SCIM `GET /Users` with `userName eq "…"` (the filter IdPs send on every sync) resolves the user through the email identifier and a membership check instead of reading every member, and the unfiltered list reads one page of memberships through the new optional `OrganizationStore.listMembersByOrganizationPage` (oldest first; without it, the service slices the full list as before), with `totalResults` from `countMembersByOrganization`. `Testing.organizationStoreConformance` checks the new method when a store implements it.

`./sql`'s `AdminUserStore.listUsers` searches, orders and pages in SQL (`LIKE … ESCAPE`, `ORDER BY` the earliest email then id, `LIMIT` / `OFFSET`), counts matches with `COUNT(*)`, and selects explicit columns, so `password_hash` is never read. Its order is now the database's binary order of the addresses instead of `localeCompare`. `AdminService.listUsers` caps `limit` at the new `AdminConfig.maxListLimit` (default 100) and applies it when no limit is given.
