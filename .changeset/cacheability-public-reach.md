---
"@thomasfosterau/effect-auth": minor
---

`Cacheability.publicReach` and `publicReachByType` add a drift guard for viewer-less caches (#191). They compile each resource type's read scope for the anonymous principal and classify the type. `All` means every row is public, so a cache may admit the type wholesale. `Some` means only the rows a filter admits are public: check each representation with `publiclyServeable`. `None` means no row is public. `Undecided` means the policies read rows in a way a scope can't express, and it never counts as public. Pin the result in a test: a policy change that moves a type from public to owned then fails the build, where a hand-kept list of public types would go stale without anyone noticing.
