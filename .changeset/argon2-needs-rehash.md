---
"@thomasfosterau/effect-auth-argon2": minor
---

`argon2Hasher` now implements `needsRehash`: a stored hash weaker than the configured costs (another variant, a lower `m`, `t` or `p`, or a shorter salt or digest), or one `verify` refuses, is re-hashed on the user's next successful sign-in.

On Cloudflare Workers the verify ceiling's default `maxMemoryKiB` is now `65536` (64 MiB, the new `workerdVerifyLimits`) rather than `131072`, a Workers isolate's whole memory, so one verify at the ceiling cannot exhaust it. A configured `memoryCost` above it raises it to that cost, and a configured `maxMemoryKiB` still wins. A Workers deployment holding stored hashes over 64 MiB must set `maxMemoryKiB` to keep verifying them. The README says what to set on Workers.
