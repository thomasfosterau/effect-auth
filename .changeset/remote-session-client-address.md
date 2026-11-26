---
"@thomasfosterau/effect-auth": minor
"@thomasfosterau/effect-auth-sveltekit": minor
---

The SvelteKit adapter and `Http.RemoteSession` no longer forward the browser's own `x-forwarded-for` and `cf-connecting-ip` to the auth service, since off Cloudflare the browser chose their values. They send the client address the app knows in one header instead (`x-forwarded-for` by default), which the auth service trusts with `ClientIP.trustedHeader`.

- `RemoteSession.make` takes `clientAddress` and `clientAddressHeader`, and `read`, `readApiKey`, `relay` and `resolveAtEdge` take a per-call `clientAddress`. Forward the browser's headers as before with `headers: { also: ["cf-connecting-ip"] }` when an edge in front of the app sets them.
- `relay` answers `400` without a call when the target would leave the auth service's origin (a pathname starting `//` or `/\`).
- SvelteKit's `ActionEvent` and `HandleEvent` gain `getClientAddress`. The credential helpers send it by default (`clientAddress`, `clientAddressHeader`, and `forwardClientIpHeaders` to opt back in).
- `handle`'s `lookup` receives the event and may answer a `SessionLookup` (what `RemoteSession.read` answers). The hook appends its `Set-Cookie` lines to the response, so the cache cookie keeps refreshing and a stale cookie is cleared, except for an API-key or bearer caller.
