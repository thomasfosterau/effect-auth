# @thomasfosterau/effect-auth-vue

Vue 3 bindings over `@thomasfosterau/effect-auth-client`: `useSession` / `useListSessions` composables, `authClientPlugin` / `provideAuthClient` / `useAuthClient`, and six headless single-file form components with exported default labels.

## Boundary

Archetype **Framework binding** (`.fallowrc.json` zone `bindings`, which may import only `client`). Peer: `vue` (`catalog:peers`, `>=3`) and nothing else. Depends on `@thomasfosterau/effect-auth-client`, imported as types only. Imports nothing from `effect` or from core. Built by `vp build` (library mode) plus `vue-tsc --emitDeclarationOnly`.

## Invariants

- **`vue-tsc` checks this package without the Effect plugin** (TS6 JS API, not the tsgo-patched `tsc`), so no Effect diagnostics or `@effect-diagnostics` directives apply. That holds only while `src/` imports nothing from `effect`; the first such import needs a deliberate check.
- **Thin over the client**: the composables adapt `client.session` and `client.listSessions`; no fetching or caching of their own.
- **Subscriptions are released with the current effect scope** (`onScopeDispose`); outside one, a composable warns and the caller must call `.dispose()`.
- **Parity with the other bindings** (DESIGN.md D8): the same capability set as `-react`, `-svelte` and `-solid`. A feature added here is added to all four.
- **Forms never navigate**: they emit `success` / `error`; `EmailOtpForm` emits `success` only for the session-yielding step; `PasswordResetConfirmForm` emits `error` with a plain `Error` on a mismatch without a request.
- **No CSS ships.** Semantic markup with stable `ea-*` classes; `classes` replaces defaults; `labels` merges over the exported defaults (`signInFormLabels`, …). Class names and labels are public API; server messages render verbatim.
- A component that finds no client throws on mount, naming the plugin, `provideAuthClient` and the `client` prop.

## Terms

- **Client injection** — `authClientKey`, the `InjectionKey` the plugin and `provideAuthClient` provide and `useAuthClient` injects.
