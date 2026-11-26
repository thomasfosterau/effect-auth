---
"@thomasfosterau/effect-auth-drizzle": minor
---

`ownedListFilter` renders the group and moderation axes. `OwnedColumns` gains optional `unapproved` and `group` columns. With `unapproved`, every arm but the owner's also requires `unapproved = false`. With `group`, a signed-in member also lists published `group` rows whose group is in their group set, nested as a `group IN (SELECT …)` subquery. The new `isMemberLayer({ isMember, groupsQuery })` provides `Auth.OwnedAccess.IsMember` over an application's membership table. A table without these columns lists as before.
