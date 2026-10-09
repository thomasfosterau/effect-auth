---
"@thomasfosterau/effect-auth": patch
---

`pbkdf2Hasher().verify` now refuses a stored iteration count above a cap before running PBKDF2, as `scryptHasher` already does for N, r and p. A crafted `pbkdf2-sha256$<iterations>$…` hash could previously make `verify` run PBKDF2 at up to Node's 2³¹−1 (about 3,500 times the 600,000 default, minutes of CPU per attempt); exploiting it needs write access to the password-hash store. The refusal is a `HashingError` ("Invalid hash parameters: …"), and `needsRehash` returns true for such a hash.

The cap is max(5,000,000, the configured `iterations`), so the hasher's own hashes always verify, including at a configured count above 5,000,000. A non-finite, fractional or out-of-range `iterations` option does not raise the cap. A hash written at more than 5,000,000 iterations verifies only on a hasher configured at that count or higher, so lowering `iterations` below such a count makes those hashes unverifiable (#328).
