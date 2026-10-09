---
"@thomasfosterau/effect-auth": minor
---

Client IP resolution can trust one named header. `TrustedProxyConfig` has a third form, `{ trustedHeader: "<name>" }`, which reads only that header and takes it as the client address when it holds exactly one IPv4 or IPv6 address. An absent, empty or malformed value, or a comma-separated list, falls back to the socket address. `X-Forwarded-For` and every other header are never read.

Two named forms sit on the `ClientIP` service. `ClientIP.trustedHeader(name)` builds that configuration, and `ClientIP.cloudflare` is the preset that trusts `CF-Connecting-IP`. Pass either as `trustedProxy` to `Http.make`, or to `clientIPLayer`, so per-IP rate limits and audit key on the visitor's address behind Cloudflare. The trust assumption is opt-in: it holds only when the app is reachable solely through that edge, and the TSDoc and README state it.
