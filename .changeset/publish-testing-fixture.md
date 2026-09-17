---
"@thomasfosterau/effect-auth-client": minor
---

Publish testing fixture as a public entry point at `@thomasfosterau/effect-auth-client/testing`. The fixture provides a fully functional in-memory effect-auth server and cookie-jar fetch for end-to-end testing. This unblocks consumers who previously had to hand-roll their own test harness (see #180).

Also adds `effect` to peerDependencies (range `>=4.0.0-rc.112`) since fixture.ts imports Effect's `Layer` and `Effect` utilities.
