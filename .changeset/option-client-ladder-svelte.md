---
"@thomasfosterau/effect-auth": minor
"@thomasfosterau/effect-auth-svelte": minor
---

**Breaking:** the browser client, the session Atoms, the ladder and the Svelte binding answer "nothing" with `Option`.

- `./client`: `getSession()` resolves `Option<SessionWithUserView>` (`None` on a `401`). `AuthClientOptions` and the send payloads spell their optional members `readonly x?: T`. The client now imports `effect/Option` at runtime, its only Effect module.
- `./client/atoms`: `SessionResult` is an `AsyncResult<Option<SessionWithUserView>, AuthClientError>`; `data` and `error` (on the Atoms and on `SessionState` / `SessionListState`) are `Option`s. The cross-tab message carries no `data` key when signed out.
- `./ladder`: `hasAtLeast` takes the holder as `Option<RungHolder>` (`Option.none()` is anonymous). The module imports `effect/Option`, and nothing else.
- `effect-auth-svelte`: `$session.data` and `$sessions.data` are `Option`s, so templates unwrap them (`Option.isSome($session.data)`). `effect` is now a runtime peer (`effect/Option`). A form's `captchaToken` prop returns `Option<string>`, and its optional props are `readonly x?: T`.
