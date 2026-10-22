# @thomasfosterau/effect-auth-client

The browser client: `createAuthClient` (typed methods over the effect-auth HTTP contract, plain `fetch`) with an observable session store, plus `./testing`, an in-memory server fixture for end-to-end tests.

## Boundary

Archetype **Client** (`.fallowrc.json` zone `client`, which may import `core` and `ladder`). Peer: `effect` (`catalog:peers`). Depends on `@thomasfosterau/effect-auth`. Entry points: `.` (`src/index.ts` → `Client.ts`) and `./testing` (`src/testing/fixture.ts`). The four framework bindings depend on this package and on nothing else in the workspace.

## Invariants

- **The `.` entry has no runtime imports.** `Client.ts` imports core with `import type` only (the wire types under `Auth.Http`), so nothing server-side and no Effect runtime reaches a browser bundle. A value import from core or `effect` in `Client.ts` breaks that; only `./testing` may import core at runtime.
- **One method per contract endpoint, named after it**, typed with the contract's own payload and view types, so a contract change is a compile error here. Optional server modules answer `404`; a method existing does not mean the server mounted the feature.
- **Every request sends `credentials: "include"`**; a non-2xx rejects with `AuthClientError` carrying `status` and the server's JSON `message` (else the status text). JSON is detected by the media-type essence (`application/json` or `+json`), not a substring.
- **The session store is lazy and refetch-skipping**: the first `subscribe` triggers the `/session` fetch; the state starts `isPending: true`; a `401` is `data: null`, not an error; a transient failure keeps the last `data` and sets `error`; session-changing calls refetch only while something is subscribed; an out-of-order refetch result is dropped.
- **Background refresh is opt-in and degrades to a no-op** outside a browser (`intervalMs`, `onFocus`, `crossTab` via `BroadcastChannel`); it starts with the first subscriber and stops with the last.
- **The second-factor continuation refuses an expired challenge locally**, without a request; the server enforces expiry regardless.
- **`./testing` runs the real `Auth.Http.make` handler** over in-memory stores with features off by default (so unconfigured endpoints answer `404`), and `makeCookieJarFetch` emulates the browser's cookie jar. It is published (`tsconfig.json` includes it); the module header that says otherwise is stale.

## Terms

- **Session store** — `client.session`: `get`, `subscribe`, `refetch` over `{ data, isPending, error }`; the contract every binding adapts.
- **Mutating call** — a session-changing request followed by a refetch when observed (`AuthClientPluginContext.mutating`).
- **Plugin** — `definePlugin(install)` adding typed methods via `client.extend`.
