---
"@thomasfosterau/effect-auth": minor
---

Add the two viewer-less-cache questions, kept apart (#191). `Cacheability.publiclyServeable(axes)`
answers whether a representation may be stored in and served from a cache with no viewer in its key,
failing closed on every declared axis (a present value must be exactly the serveable literal; a
required axis that is absent is not serveable; an `absent: true` axis such as `deletedAt` refuses any
value). `OwnedAccess.serveableAxes` are those axes derived from the owned-read policy, and admit a row
exactly when every viewer, anonymous included, may see it. `Cacheability.bypassesForFreshness(guards,
axes)` answers the separate question of whether the current viewer must be routed around a
public-only cache, and `Cacheability.shouldIncludeDeleted(guards, viewDeleted)` requires both the
opt-in and the rung. The module documents the `private, no-store` rule for any response rendered
after a principal was resolved, and the ordering that makes it enforceable.
