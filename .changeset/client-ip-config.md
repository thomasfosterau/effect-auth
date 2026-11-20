---
"@thomasfosterau/effect-auth": patch
---

`Http.make` and `Http.makeAsync` refuse a `trustedProxy: { hopCount }` that is negative or not an integer with `ClientAddressConfigError` at startup, instead of starting a handler that resolves no client address and refuses every rate-limited request. `resolveClientIP` now canonicalises the socket address the way it reads a header entry (RFC 5952 for IPv6, dotted IPv4 for an IPv4-mapped address, no zone ID), so one IPv6 visitor gets one rate-limit key whichever path the address came by.
