---
"@thomasfosterau/effect-auth-alchemy": minor
---

Raise the `effect` peer floor to `>=4.0.0` (from `>=4.0.0-rc.118`). The package's `alchemy` peer, `>=2.0.0-beta.80`, itself requires `effect ^4.0.0`, so no `effect` release candidate could satisfy both peers; the declared range now says so. The other effect-auth packages keep `effect >=4.0.0-rc.118`.
