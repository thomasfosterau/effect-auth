---
"@thomasfosterau/effect-auth": minor
---

Session context is now separable from session resolution, so a runtime that never saw an HTTP
request can be handed an already-resolved session and run gated code (#185).

`CurrentSession`, `CurrentUser` and `MaybeCurrentSession` move to a new top-level
`SessionContext` module. They were previously declared inside `http/HttpMiddleware.ts` and
provided in exactly one place — the middleware's handler wrapper — so the only way to carry a
session was to be inside an `HttpApi` handler. That does not fit a SvelteKit `hooks.server.ts`
that resolves the session into `event.locals`, a Worker route that dispatches before the router
runs, or a test harness whose whole job is "run this effect as this fixture viewer".

New, all additive:

- `SessionContext.authenticatedLayer(resolved)` — provides `CurrentSession`, `CurrentUser`,
  `MaybeCurrentSession` (as `Option.some`) and `CurrentPrincipal` from a `SessionWithUser`.
- `SessionContext.anonymousLayer` — `MaybeCurrentSession` as `Option.none()`. It deliberately
  provides no `CurrentUser` and no `CurrentPrincipal`: there is no user, and inventing one would
  let gated code type-check against a context that cannot satisfy it.
- `SessionContext.layer(resolved)` — takes whatever an app edge produced (a `SessionWithUser`, an
  `Option` of one, `null`, `undefined`) and provides the read-path service. It provides
  `MaybeCurrentSession` only, because the richer services are conditional on a session having
  resolved — code given this layer has to handle the anonymous branch.
- `SessionContext.userLayer(user)` / `userSessionLayer(session, user)`, `SessionContext.principalOf`,
  and the accessors `currentUserOption`, `currentSessionOption`, `isAuthenticated`,
  `requireCurrentUser`, `requireCurrentSession`.
- `Errors.NotAuthenticatedError` (`NOT_AUTHENTICATED`) — the authentication counterpart to
  `PermissionDeniedError`, raised by the failing accessors so a guard can turn an anonymous
  context into a typed failure without reaching for the HTTP layer's `Unauthorized`.

`AuthMiddleware` now also provides `MaybeCurrentSession` (always `Option.some` there, since it
only reaches the handler when a session resolved). That is what makes one effect written against
the read-path service run unchanged under required auth, under `OptionalAuthMiddleware`, and under
`SessionContext.layer` at a non-HTTP edge.

**Nothing to migrate.** `CurrentUser` keeps its `Types.User` type and its `@effect-auth/CurrentUser`
tag string; `Http.CurrentSession` / `Http.CurrentUser` / `Http.MaybeCurrentSession` still resolve,
re-exported from their new home. Widening `AuthMiddleware`'s `provides` only ever removes
requirements from a handler, so existing handlers are unaffected.

Read-path code should depend on `MaybeCurrentSession` rather than `CurrentUser`: "signed out" is a
value there (`Option.none()`), so a predicate like "may this viewer see deleted rows?" can answer
`false` for an anonymous caller instead of failing — which is most of a real read path.
`requireCurrentUser` is the derived convenience for the gated case, not the other way round.
