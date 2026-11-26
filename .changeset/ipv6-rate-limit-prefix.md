---
"@thomasfosterau/effect-auth": minor
---

Key IPv6 clients on their /64 in every address-keyed rate limit: `Http.make`'s `ipRateLimit`, `IPRateLimitPlugin` and the dynamic client registration limit. Every address of one /64 now draws on one budget, so rotating through a customer's block no longer earns a fresh one per address; IPv4 keying is unchanged. `ipRateLimit.ipv6PrefixLength` and `IPRateLimitPlugin({ ipv6PrefixLength })` change the length (an integer from 1 to 128, `128` restoring per-address keys); any other value fails at startup with `RateLimiterConfigError`. New exports: `rateLimitAddressKey`, `isIpv6RateLimitPrefix` and `DEFAULT_IPV6_RATE_LIMIT_PREFIX`. Existing IPv6 rate-limit rows are keyed per address and expire with their windows.
