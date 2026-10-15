---
"@thomasfosterau/effect-auth": minor
---

Sign-up can answer without disclosing whether an address is registered, and delivery sends run off the response path.

- `EmailPasswordConfig.antiEnumeration` (default `false`): a sign-up for an
  address another user holds answers like a fresh one rather than with
  `EmailInUseError`. It hashes the submitted password (so the two branches
  cost comparable work) and answers with the same no-session result shape a
  fresh sign-up gets, built only from the caller's own input, never the real
  account's data. With the flag set, a fresh sign-up gets no immediate
  session either, so neither branch sets a cookie. With it unset, a duplicate
  fails with `EmailInUseError`.
- Each callback from `emailCallbacks`/`smsCallbacks` in `Delivery.ts`
  dispatches `sender.send` on a detached fiber, so a flow that sends mail or
  SMS on only one of its branches (like sign-up's fresh-registration branch)
  does not reveal that branch through response timing. A failed send never
  fails the flow that triggered it; it is logged and counted in
  `effect_auth_delivery_sends_total`.
