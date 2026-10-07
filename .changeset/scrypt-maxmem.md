---
"@thomasfosterau/effect-auth": patch
---

scrypt hashing and verifying no longer fail when `p + 2 > N` (for example a stored hash with N = 4, p = 8): `maxmem` is now `128 * r * (N + p + 2)`, the memory OpenSSL's scrypt needs.
