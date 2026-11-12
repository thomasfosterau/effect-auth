---
"@thomasfosterau/effect-auth": minor
---

Security hardening (#661): an empty entity id names no entity, so it never matches. Before, `Entity.ref("User", "")` was an ordinary principal. An owner permit (`resource.owner == principal`) granted it every row whose owner was `""`, in `Policy.decidePure` and in `ReadScope.compile` alike, so an integrator that used the empty id as a "no user" stand-in granted those rows to signed-out callers.

- **Decoding:** `Entity.EntityRef`'s `id` is now `Schema.NonEmptyString` (breaking). A stored policy, a request or a logged slice that names `""` fails to decode.
- **Decisions:** `Policy.decidePure` and `Policy.decide` deny a request whose principal, action or resource has an empty id before any policy runs, custom predicates included. `Policy.Decision["reason"]` gains `"invalid-request"` (breaking for exhaustive matches), and `Policy.enforce` and the HTTP `Forbidden` carry it. `Policy.isWellFormed(request)` is the check.
- **Read scopes:** `ReadScope.compile` returns `ReadScope.deny` for an empty-id principal or action. An empty-id entity value never compiles to an `Eq` atom, so a scope never admits an empty owner column for it.
- **Equality:** `Entity.refEquals`, `Entity.attributeValueEquals` and `Entity.entityIn` are `false` whenever a side has an empty id, at any depth and even against itself. `Entity.namesEntity(ref)` is the new predicate. `Entity.ref` stays total.
- **Guards:** `Guard.make` reads a viewer whose `id` is empty as anonymous. `OwnedAccess` and `ReferenceAccess` follow, so `canView` admits only public rows and `readScope` is `public`.

Migration: don't use an empty id for a signed-out caller. Give it a principal of its own type, such as `Anonymous::"anonymous"`, which user-typed policies never match. Handle `"invalid-request"` wherever you switch on `Decision.reason`.
