---
"@thomasfosterau/effect-auth-drizzle": patch
---

`ownedListFilter`'s docs now say what it does not render yet: the new `group` visibility and the moderation axis of `Auth.OwnedAccess` (#637). A `group` row lists only for its owner, and the read scope's `groups` set is ignored.
