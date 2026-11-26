---
"@thomasfosterau/effect-auth": minor
---

**Breaking:** `Http.make` and `Http.makeAsync` no longer take `allowMissingClientIp`. It had stopped doing anything: with a `trustedProxy` an address is always resolved, and without one the handler refuses to start whenever an address-keyed limit is on. Remove the option; give the handler a `trustedProxy`, or serve without the IP limit with `ipRateLimit: false`.
