---
"@thomasfosterau/effect-auth-drizzle": minor
---

Add `UserServiceStore`, the drizzle-backed `Auth.UserServiceStore` that `UserService`, `AccountManagementService` and `AdminService` need, so `Http.make`'s services can run on Drizzle (#728). `UserServiceStore.layer(schema)` takes a dialect's tables or a `defineSchema` mapping; `get` reads through `UserStore`'s projection, `update` writes the user's name, image, `updatedAt` and attributes (promoted attributes to their own columns) in one `UPDATE`, and `delete` removes the user row, with the semantics of core's `/sql` store. Merge it beside `Drizzle.layer()` like the other stores beyond sign-in.
