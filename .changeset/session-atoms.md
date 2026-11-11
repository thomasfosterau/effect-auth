---
"@thomasfosterau/effect-auth": minor
"@thomasfosterau/effect-auth-svelte": minor
---

The client session is now an `effect/reactivity` Atom graph (#206). **Breaking.**

`@thomasfosterau/effect-auth`: the new `./client/atoms` subpath's `makeSessionAtoms(client, options?)` exposes the session read (`result`, an `AsyncResult`), its derived states (`state`, `data`, `isSignedIn`, `isPending`, `error`) and the signed-in user's session list (`sessions`, `sessionsState`) as Atoms, read through the application's own `AtomRegistry`. The semantics of the old store carry over: the read is lazy and starts pending, a `401` is `data: null`, a transient failure keeps the last session and sets `error`, a superseded refetch never lands, and session-changing calls refetch only while the session is observed, now resolving once that refetch has settled. A session change reaches every Atom that reads the session through the graph. `./client` itself still imports nothing at runtime: it drops its session store and instead announces session-changing calls through `client.onSessionChange(listener)` and `client.invalidateSession()`.

`@thomasfosterau/effect-auth-svelte`: the stores are now adapters over those Atoms. `atomStore(registry, atom)` turns any Atom into a readable store; `sessionStore` and `listSessionsStore` take `(registry, atoms)`. `effect` is a new peer dependency, used for its types only. The form components are unchanged.

Migration:

- `client.session.subscribe(listener)` / `client.session.get()` → `const auth = makeSessionAtoms(client)` once, then `registry.subscribe(auth.state, listener, { immediate: true })` / `registry.get(auth.state)`. `SessionState` keeps its `{ data, isPending, error }` shape and moves to `./client/atoms`.
- `client.session.refetch()` → `registry.refresh(auth.result)`, or `await client.invalidateSession()` to wait for it.
- `createAuthClient({ refresh })` → `makeSessionAtoms(client, { refresh })`; `RefreshOptions` moves to `./client/atoms`.
- `AuthClientPluginContext.session` is gone; `mutating` notifies the session observers instead.
- Svelte: `sessionStore(client)` → `sessionStore(registry, auth)`, `listSessionsStore(client)` → `listSessionsStore(registry, auth)`. The session list now follows the session (empty, with no request, while signed out) and keeps its last data through a failed read.

Server-side hydration of the session Atoms is not part of this release.
