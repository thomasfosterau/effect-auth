---
"@thomasfosterau/effect-auth": minor
---

Security hardening (#666): an empty entity type names no entity, so it never matches, as an empty id already does (#661). Before, `Entity.ref("", "u1")` was an ordinary reference: it decoded, it equalled itself, a permit scoped to `Policy.isType("")` matched it, and an owner permit over an attribute bound to the type `""` compiled to an owner filter.

- **Decoding:** `Entity.EntityRef`'s `type` is now `Schema.NonEmptyString` (breaking). A stored policy, a request or a logged slice that names an entity of type `""` fails to decode.
- **Decisions:** `Policy.decidePure` and `Policy.decide` deny a request whose principal, action or resource has an empty type with reason `"invalid-request"`, before any policy runs, custom predicates included. `Policy.isWellFormed` checks the type as well as the id.
- **Read scopes:** `ReadScope.compile` returns `ReadScope.deny` for an empty-type principal or action, and an empty-type entity value never compiles to an `Eq` atom.
- **Equality:** `Entity.namesEntity` checks both fields, so `Entity.refEquals`, `Entity.attributeValueEquals` and `Entity.entityIn` are `false` whenever a side has an empty type, at any depth and even against itself. No type scope matches an empty type, `Policy.isType("")` included. `Entity.ref` stays total.

Migration: don't use an empty type for any entity. A signed-out caller is a principal of its own type, such as `Anonymous::"anonymous"`.
