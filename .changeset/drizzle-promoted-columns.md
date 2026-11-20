---
"@thomasfosterau/effect-auth-drizzle": patch
---

`defineSchema` throws the new `SchemaMappingError` when `users.promoted` maps an attribute onto a column already mapped to a fixed field (`id`, `name`, `image`, `passwordHash`; `createdAt`, `updatedAt` and the attribute bag are already refused by the types). Before, `UserServiceStore.update` and `EmailPasswordStore.createUser` wrote the attribute over that column, or set it to `NULL` when the attribute was absent.
