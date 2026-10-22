# @thomasfosterau/effect-auth-solid

Solid bindings over `@thomasfosterau/effect-auth-client`: `createSession` / `useSession`, `createListSessions` / `useListSessions`, `AuthClientProvider` / `useAuthClient`, and six unstyled form components.

## Boundary

Archetype **Framework binding** (`.fallowrc.json` zone `bindings`, which may import only `client`). Peer: `solid-js` (`catalog:peers`, `>=1.9.17`) and nothing else. Depends on `@thomasfosterau/effect-auth-client`, imported as types only. Imports nothing from `effect` or from core. The `.` export has a `solid` condition pointing at un-compiled JSX (`dist/source/`) for Solid-aware bundlers and a pre-compiled `vp build` output for the rest; `build` produces both plus declarations.

## Invariants

- **Thin over the client**: accessors adapt `client.session` and `client.listSessions`; no fetching or caching of their own.
- **Subscriptions are released with the reactive owner** (`onCleanup`). Called outside an owner, a primitive warns and the caller must call `.dispose()`; every primitive returns a `dispose`.
- **Parity with the other bindings** (DESIGN.md D8): the same capability set as `-react`, `-svelte` and `-vue`. A feature added here is added to all four.
- **Forms never navigate**: they report through `onSuccess` / `onError`; `EmailOtpForm` reports only the session-yielding step.
- **No CSS ships.** Semantic markup with stable `ea-*` classes (including `ea-restart`); `class` appends, `classes` replaces defaults. Class names and default labels are public API; server messages render verbatim.
- `useAuthClient()` throws a pointed error without a provider; a form's `client` prop overrides context.
- Both builds must keep shipping: the `solid` condition's source build and the compiled fallback.

## Terms

- **Accessor** — a Solid signal getter; `SessionAccessor` is one with a `dispose` attached.
