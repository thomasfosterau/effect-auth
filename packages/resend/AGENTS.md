# @thomasfosterau/effect-auth-resend

The core's `EmailSender` seam over Resend's REST API (`POST /emails`) with plain `fetch`.

## Boundary

Archetype **Vendor adapter** (`.fallowrc.json` zone `vendor-adapters`, which may import `core` and `ladder`). Peer: `effect` (`catalog:peers`). Depends on `@thomasfosterau/effect-auth` only: no Resend SDK, and none may be added. The per-feature delivery callbacks come from core (`emailCallbacks` in `Delivery.ts`); this package only sends.

## Invariants

- **Plain `fetch`, Workers-safe**: no `node:` import, no SDK; `fetch` and `baseUrl` are injectable for tests and proxies (defaults `globalThis.fetch`, `https://api.resend.com`).
- **Every `fetch` passes `redirect: "error"` and the `signal` `Effect.tryPromise` offers** (#606): a 3xx fails without a second request, so the key is sent to `baseUrl` only, and interrupting `send` aborts the request. An injected `fetch` gets the same init.
- **The API key is `Redacted`** and is unwrapped only into the `Authorization: Bearer` header. It never appears in an error, a span attribute or a log; an error body that echoes it has it replaced with `[redacted]`.
- **Every failure is an `AuthError`**: a network failure (a refused redirect included) with the thrown cause, a non-2xx response with `cause: { status, body }`. No other error type leaves `send`.
- **The error `body` is bounded**: the stream is read only until it passes `MAX_ERROR_BODY_CHARS` (1024) plus the key's length, then cancelled, and the excerpt keeps at most `MAX_ERROR_BODY_CHARS` characters, ending in `TRUNCATION_MARKER` when cut. Never read a non-2xx body with `response.text()`.
- **Rendering is keyed off `EmailMessage.purpose`**; `defaultRender` is a plain-text fallback for tests and first runs (`params.otp`, else `params.url`, else `params.token`), not a template system. Applications pass `render`.
- One span per send, `effect-auth-resend.send`, with only the `purpose` attribute (never the recipient or the params).

## Terms

- **Purpose** — `DeliveryPurpose` from core (`"magic-link"`, `"email-verification"`, OTP purposes, …): the stable tag a renderer switches on.
