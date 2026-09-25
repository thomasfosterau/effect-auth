---
"@thomasfosterau/effect-auth": minor
"@thomasfosterau/effect-auth-drizzle": minor
---

Make the `role` attribute safe to authorize on (#193, the parts that pair with the ladder).

- **Server-only attributes.** `UserService.updateUserAttributes` now refuses — with
  `InvalidInputError`, writing nothing — any key in `UserServiceConfig.serverOnlyAttributes`, which
  defaults to `["role"]`: a profile-update path built on it can no longer let a user set their own
  rung. **Behaviour change:** code that set `role` through `updateUserAttributes` must move to
  `AdminService.setRole` (or pass `UserService.layer({ serverOnlyAttributes: [] })` to opt out).
- **Constrained values.** `AdminConfig.roles` (an app's `Ladder` satisfies it) makes `setRole` and
  `createUser` refuse a role off the ladder with `AdminError`, whichever door the role comes in by.
- **Declared once.** `LadderSchema.rung(ladder)` is the ladder's rungs as a `Schema`, and
  `@thomasfosterau/effect-auth-drizzle`'s `ladderCheck(column, ladder)` is the matching `CHECK`
  expression (rungs inlined as quoted literals), so the type, the runtime check and the database
  backstop come from one declaration.
