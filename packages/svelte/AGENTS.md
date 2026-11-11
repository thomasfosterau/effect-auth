# @thomasfosterau/effect-auth-svelte

Svelte 5 bindings over the core's browser client: `atomStore` (any `effect/reactivity` Atom as a readable store), `sessionStore` / `listSessionsStore` over the session Atoms of `@thomasfosterau/effect-auth/client/atoms`, `setAuthClient` / `getAuthClient` context, and six unstyled rune-based form components.

## Boundary

Archetype **Framework binding** (`.fallowrc.json` zone `bindings`, which may import `core` — in practice only its `/client` and `/client/atoms` subpaths — and `ladder`). Peers: `svelte` and `effect` (`catalog:peers`); `effect` for the Atom and registry types only. Depends on `@thomasfosterau/effect-auth` for `/client` and `/client/atoms`, imported as types only. Imports nothing from `effect` at runtime (`import type` only) and nothing from the core's other entries: the stores call the registry's own methods. Built with `svelte-package` and resolved through the `svelte` export condition; `scripts/postbuild.mjs` strips compiled tests and the `.svelte-kit/__package__` staging copy from `dist/`. Type-checked by `svelte-check` (TS6 JS API, no Effect plugin).

## Invariants

- **Thin over the Atoms**: the stores are `atomStore` over `SessionAtoms.state` and `.sessionsState`; no fetching, caching or state of their own. The registry is the caller's (one per page, shared with its other Atoms); the binding never creates one.
- **The stores implement Svelte's readable-store contract directly** (`subscribe(run)` calls `run` immediately, via `registry.subscribe(atom, run, { immediate: true })`, and returns the unsubscribe), so `$store` works without importing `svelte/store`. Subscribing mounts the Atom; unsubscribing unmounts it.
- **`atomStore` is the Svelte↔Atom binding**, kept minimal so it can move to a shared Svelte Atom binding (effect-svelte) later without changing the session stores' contract.
- **Forms never navigate**: they report through `onSuccess` / `onError`; `EmailOtpForm` reports only the session-yielding step and marks its `<form>` `data-step="request" | "verify"`. They call the client only; the session Atoms observe those calls.
- **No CSS ships.** Semantic markup with stable `ea-*` classes (including `ea-restart`); `class` appends, `classes` replaces defaults. Class names and default labels are public API; server messages render verbatim.
- `getAuthClient()` throws a pointed error when nothing above called `setAuthClient`; a form's `client` prop overrides context.
- No published file may be a compiled test: keep the postbuild step when changing the build.
- SSR hydration of the session Atoms is not implemented (follow-up to #206).

## Terms

- **Form outcome** — `AuthSuccess` or `StatusResponse`, the client's result types re-exported; `onError` receives whatever the client threw.
- **`FormFailure`** — a rendered failure: its message plus the field it implicates (`null` for a server failure, which drives `aria-invalid`).
- **Session Atoms** — `SessionAtoms` from `makeSessionAtoms(client)` in the core's `/client/atoms`; the stores' only source.
