---
"@thomasfosterau/effect-auth": minor
---

Client IP resolution can trust one named header. `TrustedProxyConfig` has a third form, `{ trustedHeader: "<name>" }`, which reads only that header and takes it as the client address when it holds exactly one IPv4 or IPv6 address. An accepted IPv6 address is canonicalised (RFC 5952) and an IPv4-mapped one becomes dotted IPv4. An absent, empty or malformed value, a comma-separated list, or duplicate headers fall back to the socket address; a Web `Request` under `Http.make` has none, so then no address resolves (#358). `X-Forwarded-For` and every other header are never read.

Two named forms sit on the `ClientIP` service. `ClientIP.trustedHeader(name)` builds that configuration, and `ClientIP.cloudflare` is the preset that trusts `CF-Connecting-IP`. Pass either as `trustedProxy` to `Http.make`, or to `clientIPLayer`, so per-IP rate limits key on the visitor's address behind Cloudflare. The trust assumption is opt-in: it holds only when the app is reachable solely through that edge, and the TSDoc and README state it.
