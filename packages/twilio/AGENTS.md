# @thomasfosterau/effect-auth-twilio

The core's `SmsSender` seam over Twilio's Messages API (`POST /2010-04-01/Accounts/:sid/Messages.json`) with plain `fetch`.

## Boundary

Archetype **Vendor adapter** (`.fallowrc.json` zone `vendor-adapters`, which may import `core` and `ladder`). Peer: `effect` (`catalog:peers`). Depends on `@thomasfosterau/effect-auth` only: no Twilio SDK, and none may be added. The per-feature callbacks come from core (`smsCallbacks` in `Delivery.ts`); this package only sends.

## Invariants

- **Plain `fetch`**, injectable together with `baseUrl` (defaults `globalThis.fetch`, `https://api.twilio.com`). The archetype requires Workers safety; the Basic-auth header is built with `btoa` (`src/Twilio.ts`). Don't add Node globals: lint rejects `Buffer` outside Node-only code (#481).
- **Every `fetch` passes `redirect: "manual"` and the `signal` `Effect.tryPromise` offers** (#606). Never `"error"`: workerd's `fetch` throws a `TypeError` for it on every request, a 200 included (`src/Workerd.test.ts` runs the sender in the real `workerd` binary and pins this). A response with status 300–399 or 0, or of type `"opaqueredirect"`, fails as an `AuthError` with `cause: { status }`; decide on the status, never on `type` alone (workerd and Node return the real 3xx as `type: "default"`). Its body is cancelled unread and `Location` is never read, so the credentials are sent to `baseUrl` only and there is no second request. Interrupting `send` aborts the request. An injected `fetch` gets the same init.
- **The auth token is `Redacted`** and unwrapped only into the `Authorization: Basic` header. It never appears in an error, a span attribute or a log; an error body that echoes the token or the Basic credentials has them replaced with `[redacted]`.
- **Every failure is an `AuthError`**, never a defect: network failures carry the thrown cause; a redirect carries `cause: { status }`; a non-2xx carries `cause: { status, body }`, and Twilio's `{ code, message }` body, when it parses, is folded into the message; an error body whose stream fails carries the stream's error.
- **The error `body` is bounded**: the stream is read only until it passes `MAX_ERROR_BODY_CHARS` (1024) plus the longest credential's length, then cancelled, and the excerpt keeps at most `MAX_ERROR_BODY_CHARS` characters, ending in `TRUNCATION_MARKER` when cut. The message embeds only that excerpt. Never read a non-2xx body with `response.text()`.
- **The body is form-encoded** (`Body`, `From`, `To`), as Twilio's API requires.
- **Rendering is keyed off `SmsMessage.purpose`**; `defaultRender` is a plain fallback (`params.otp`, else `params.token`). Applications pass `render`.
- One span per send, `effect-auth-twilio.send`, with only the `purpose` attribute.

## Terms

- **Purpose** — `DeliveryPurpose` from core (`"phone-otp:<purpose>"`, `"second-factor-otp"`, …).
