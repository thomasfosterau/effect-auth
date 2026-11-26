---
"@thomasfosterau/effect-auth": patch
---

Document the CPU cost of `pbkdf2Hasher`'s default 600,000 iterations on Cloudflare Workers (about 75 ms per hash or verify, more than the Free plan's 10 ms), and that the scrypt verifier's default needs a Workers isolate's whole 128 MiB. The workerd suite now hashes and verifies at the PBKDF2 default.
