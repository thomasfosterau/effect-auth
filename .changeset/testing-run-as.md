---
"@thomasfosterau/effect-auth": minor
---

Add the `@thomasfosterau/effect-auth/testing` subpath with `runAs` / `runAsViewer` (and their `layerAs` / `viewerLayerAs` layers): run an Effect as a fixture principal, signed in or anonymous, in one call. Signed in, the effect gets the session context the required-auth middleware provides; `runAsViewer` also provides the app's own viewer service through `SessionContext.viewerLayer`.
