---
"@thomasfosterau/effect-auth": minor
"@thomasfosterau/effect-auth-drizzle": minor
---

Add owned-material read access and its drizzle rendering (#190).

`Auth.OwnedAccess.make({ guards, viewPrivate })` interprets a three-state visibility axis
(`public | followers | private`) plus an orthogonal `draft` flag, in two shapes built from the same
facts: `canView(row)`, the per-row predicate (never fails — a `false` is a 404 to the caller,
decided by the policy kernel over `OwnedAccess.policies`), and `readScope`, the per-request
`all | public | member(userId, following)` scope a list renders as its `WHERE`. The `followers`
state resolves through the `IsFollower` service (a row check plus the viewer's follow set) read with
`Effect.serviceOption`, so a runtime that does not provide it fails closed; `isFollowerNever` makes
that explicit.

`@thomasfosterau/effect-auth-drizzle` adds `ownedListFilter(columns)(scope)`, which renders the scope
over any table's or view's owner / visibility / draft columns — the follow set nested as an
`owner IN (SELECT …)` subquery, never a materialised list — and `isFollowerLayer`, the follower seam
over an application's own follow table. A property test runs the rendered filter and `canView` over
one corpus in PGlite and requires them to agree on every row.
