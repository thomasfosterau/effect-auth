---
"@thomasfosterau/effect-auth": minor
---

`OwnedAccess.policies` are read policies (#387): each `owned:public`, `owned:owner`, `owned:view-private` and `owned:follower` permit is scoped to `Action::"read"`. Handed to an `Authorizer` alongside write gates, the set allows a user nothing on update or delete, including on a public row. `canView` and `readScope` decide reads only, and they agree with these policies on every read, so the drizzle `ownedListFilter` agreement holds.
