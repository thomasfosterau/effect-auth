---
"@thomasfosterau/effect-auth": minor
---

Add a credential class to the resolved principal, distinguishing an interactive session
(the session cookie) from a machine credential (an `Authorization: Bearer/Token` header —
the same delivery path a consuming app's own API-key middleware would use), and gate
minting a new API key on it (#198).

- `Authorizer.CredentialClass` (`"interactive" | "machine"`) and `Authorizer.CurrentCredential`
  — a `Context.Service`, mirroring `CurrentPrincipal`, carrying how the current principal
  authenticated. Kept as its own service rather than folded into the principal entity or the
  session record: neither a bare `EntityRef` nor a machine credential (which has no
  `Types.Session`) has a natural place to carry it, and a separate tag lets non-HTTP callers
  (a worker, a CLI, an RPC handler) provide it without fabricating either.
- `Authorizer.authorize`/`check` merge `CurrentCredential`, when present, into the decision's
  `context.credentialClass` attribute — visible to declarative policies
  (`Condition.attr("context", "credentialClass")`) and custom policy predicates alike, not
  just to the HTTP layer. The ambient value always wins over anything a caller passes in
  `AuthorizeInput.context.credentialClass`, so a call site cannot spoof its own class.
- `Http.AuthMiddleware`/`OptionalAuthMiddleware` now also provide `CurrentCredential`
  alongside `CurrentPrincipal`: `"interactive"` for the session cookie, `"machine"` for the
  `Authorization` header. `Http.credentialClassFromRequest` exposes the same classification
  for handlers built outside the middleware.
- The built-in `POST /api-keys` (`apiKeyCreate`) endpoint now requires an interactive
  credential, failing with `Forbidden` (403, added to its error union) for a bearer-delivered
  session — closing the concrete case this issue named ("a key can mint a key") for the
  API surface this library ships, and giving consuming apps the same primitive
  (`CurrentCredential` + a declarative policy) to gate their own sensitive, session-only
  operations.
