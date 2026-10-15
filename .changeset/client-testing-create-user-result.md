---
"@thomasfosterau/effect-auth-client": patch
---

The `./testing` in-memory server's `createUser` seams resolve to core's `CreateUserResult`, `{ user, created: true }`, since each call inserts a new user (#406). No change to the fixture's own API.
