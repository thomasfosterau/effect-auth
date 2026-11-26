---
"@thomasfosterau/effect-auth-better-auth": minor
---

New package: BetterAuth as the backend for effect-auth's services. `BetterAuthSessions.lookup` resolves a request's session through `auth.api.getSession` and relays BetterAuth's `Set-Cookie` lines (for the SvelteKit `handle`); `sessionServiceLayer`, `usersLayer` and a read-only `IdentifierStore` implement the core's contracts over BetterAuth's internal adapter; `BetterAuthCredentials` wraps sign-up, sign-in and sign-out; `betterAuthHasher` verifies BetterAuth's scrypt hashes. Private until it is published.
