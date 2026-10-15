---
"@thomasfosterau/effect-auth": patch
"@thomasfosterau/effect-auth-drizzle": patch
---

With `antiEnumeration: true`, email and password sign-up answers an address found taken at the insert (a lost race, or a store whose `createUser` reports `created: false`) exactly as it answers one the pre-check finds taken: it hashes the submitted password and returns the same no-session result, so neither the response nor its timing tells an existing account apart (#410).

`CreateUserResult` and every `createUser` seam's docs state that a writer leaves an existing user's row unmodified: a plain `INSERT` that lets the unique index fail, or `ON CONFLICT DO NOTHING` followed by a select, and never `ON CONFLICT DO UPDATE`. effect-auth-drizzle's `SingleTableIdentifierStore` docs and README say the same for `onConflictDoNothing` and `onConflictDoUpdate`, and the README's writers return the user's `name`.
