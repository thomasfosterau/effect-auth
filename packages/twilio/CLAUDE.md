# @thomasfosterau/effect-auth-twilio

The core's `SmsSender` seam over Twilio's Messages API (`POST /2010-04-01/Accounts/:sid/Messages.json`) with plain `fetch`.

## Boundary

Archetype **Vendor adapter** (`.fallowrc.json` zone `vendor-adapters`, which may import `core` and `ladder`). Peer: `effect` (`catalog:peers`). Depends on `@thomasfosterau/effect-auth` only: no Twilio SDK, and none may be added. The per-feature callbacks come from core (`smsCallbacks` in `Delivery.ts`); this package only sends.

## Invariants

- **Plain `fetch`**, injectable together with `baseUrl` (defaults `globalThis.fetch`, `https://api.twilio.com`). The archetype requires Workers safety; the Basic-auth header is built with `Buffer.from(...)` (`src/Twilio.ts`), a Node global that Workers provides only under `nodejs_compat`. Don't add more Node globals, and prefer `btoa` when that line changes.
- **The auth token is `Redacted`** and unwrapped only into the `Authorization: Basic` header. It never appears in an error, a span attribute or a log.
- **Every failure is an `AuthError`**: network failures carry the thrown cause; a non-2xx carries `cause: { status, body }`, and Twilio's `{ code, message }` body, when it parses, is folded into the message.
- **The body is form-encoded** (`Body`, `From`, `To`), as Twilio's API requires.
- **Rendering is keyed off `SmsMessage.purpose`**; `defaultRender` is a plain fallback (`params.otp`, else `params.token`). Applications pass `render`.
- One span per send, `effect-auth-twilio.send`, with only the `purpose` attribute.

## Terms

- **Purpose** — `DeliveryPurpose` from core (`"phone-otp:<purpose>"`, `"second-factor-otp"`, …).
