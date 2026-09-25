---
"@thomasfosterau/effect-auth-drizzle": minor
---

Promote attributes to real columns (#182). The users entry of `defineSchema` takes
`promoted: { role: "role", … }` — attribute name to a column that reads back as a string, number,
boolean or `null` — and the user store (direct and batched reads) presents each promoted column in
`user.attributes` under that name, so `attributes.role` readers see the application's real, typed,
`CHECK`-constrained `users.role` column. The column is the sole authority for its key: a value under
the same key in the `jsonb` bag is ignored, and a `NULL` column leaves the key absent. The users
table's `attributes` mapping is now optional, so a table whose every attribute is a column — the
shape the applications' `users` tables have — needs no bag at all.
