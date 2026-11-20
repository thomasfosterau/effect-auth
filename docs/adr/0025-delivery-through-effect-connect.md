# Delivery goes through effect-connect

**Amends [ADR-0022](0022-package-boundaries.md)**, which kept `effect-auth-resend` and
`effect-auth-twilio` as vendor adapters by the owner's decision.

Each adapter was a hand-written `fetch` client for one vendor (redirect refusal, bounded and
redacted error bodies, a Workers test), and an application that also sent its own mail or SMS
carried a second client for the same vendor. [effect-connect](https://github.com/thomasfosterau/effect-connect),
the owner's messaging library, already holds those clients, with one service per channel
(`EmailService`, `SmsService`) and the transport rules stated once.

## Decision

1. **The core depends on `@thomasfosterau/effect-connect`** (a regular dependency, reached from the
   root through `Delivery.ts`). It brings only `effect`, which ADR-0022 rule 1 allows.
2. **`EmailSender` and `SmsSender` stay the seams.** `EmailSender.layerConnect({ from, render? })`
   and `SmsSender.layerConnect({ from?, render? })` build them over the `EmailService` /
   `SmsService` in context; `fromConnect` does the same over a service value. Rendering stays in
   the core, keyed off `purpose` (`defaultEmailRender`, `defaultSmsRender` are the fallbacks). A
   provider's `EmailSendError` / `SmsSendError` becomes an `AuthError` carrying it as `cause`.
3. **`effect-auth-resend` and `effect-auth-twilio` are removed.** Their replacements are
   `@thomasfosterau/effect-connect-resend` and `@thomasfosterau/effect-connect-twilio`. A vendor
   effect-connect lacks is added there, never as an effect-auth package.

## Consequences

- An application provides one provider layer per channel, which its own code can share.
- The vendor-specific invariants (redirects, redaction, the workerd test) live in effect-connect.
- The removed packages get no further releases; their last published versions keep working with
  the `EmailSender` / `SmsSender` contract, which did not change.
