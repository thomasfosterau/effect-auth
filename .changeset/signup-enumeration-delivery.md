---
"@thomasfosterau/effect-auth": minor
---

Close the sign-up enumeration oracle and move delivery sends off the response path.

- `EmailPasswordConfig` gains an opt-in `antiEnumeration` flag. When set, the
  duplicate-registration branch of `signUp` no longer returns
  `EmailInUseError`: it hashes the submitted password (so the two branches
  cost comparable work) and answers with the same no-session result shape a
  fresh sign-up gets, built only from the caller's own input — never the
  real account's data. Enabling it also suppresses the immediate session on
  the fresh branch, so neither branch sets a cookie. Default is `false`;
  existing behaviour is unchanged unless explicitly opted in.
- Every callback derived by `emailCallbacks`/`smsCallbacks` in `Delivery.ts`
  now dispatches its `sender.send` on a detached fiber instead of awaiting
  it inline, so a flow that sends mail/SMS on only one of its branches (like
  sign-up's fresh-registration branch) no longer leaks that branch through
  response timing. A failed send never fails the flow that triggered it; it
  is logged and counted via a new `effect-auth.delivery_sends.total` metric
  instead.
