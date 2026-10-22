# @thomasfosterau/effect-auth-svelte

Svelte 5 bindings over `@thomasfosterau/effect-auth-client`: `sessionStore` / `listSessionsStore` (readable stores), `setAuthClient` / `getAuthClient` context, and six unstyled rune-based form components.

## Boundary

Archetype **Framework binding** (`.fallowrc.json` zone `bindings`, which may import only `client`). Peer: `svelte` (`catalog:peers`, `^5.20.0`) and nothing else. Depends on `@thomasfosterau/effect-auth-client`, imported as types only. Imports nothing from `effect` or from core. Built with `svelte-package` and resolved through the `svelte` export condition; `scripts/postbuild.mjs` strips compiled tests and the `.svelte-kit/__package__` staging copy from `dist/`. Type-checked by `svelte-check` (TS6 JS API, no Effect plugin).

## Invariants

- **Thin over the client**: the stores adapt `client.session` and `client.listSessions`; no fetching or caching of their own.
- **The stores implement Svelte's readable-store contract directly** (`subscribe(run)` calls `run` immediately and returns an unsubscribe), so `$store` works without importing `svelte/store`. `listSessionsStore` drops an out-of-order result.
- **Parity with the other bindings** (DESIGN.md D8): the same capability set as `-react`, `-solid` and `-vue`. A feature added here is added to all four.
- **Forms never navigate**: they report through `onSuccess` / `onError`; `EmailOtpForm` reports only the session-yielding step and marks its `<form>` `data-step="request" | "verify"`.
- **No CSS ships.** Semantic markup with stable `ea-*` classes (including `ea-restart`); `class` appends, `classes` replaces defaults. Class names and default labels are public API; server messages render verbatim.
- `getAuthClient()` throws a pointed error when nothing above called `setAuthClient`; a form's `client` prop overrides context.
- No published file may be a compiled test: keep the postbuild step when changing the build.

## Terms

- **Form outcome** — `AuthSuccess` or `StatusResponse`, the client's result types re-exported; `onError` receives whatever the client threw.
- **`FormFailure`** — a rendered failure: its message plus the field it implicates (`null` for a server failure, which drives `aria-invalid`).
