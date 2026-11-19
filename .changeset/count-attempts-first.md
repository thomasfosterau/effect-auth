---
"@thomasfosterau/effect-auth": minor
---

Count guesses before comparing them (#593). Email and phone OTP verification, `OtpSecondFactorService.verify`, `MultiFactorService.verifyTotp` / `verifyBackupCode` and `AccountLockoutPlugin` used to read the attempt count, compare the code or check the password, and count only afterwards. A burst of parallel requests all read the count before any of them raised it, so each request got a comparison even when the store's increment was atomic. With a cap of 3, a few hundred concurrent requests got a few hundred guesses at the code, and the lockout let a burst through in place of 5 password guesses per window. Each one now takes an atomic count first and refuses an attempt uncompared once that count passes the cap. `AccountLockoutPlugin` now acts on the record `registerAttempt` returns.

**Breaking for bring-your-own stores:**

- `EmailOtpStore.incrementAttempts` and `PhoneOtpStore.incrementAttempts` now return `number | null`. They return `null` when the pair has no code, where they used to fail with `AuthError`.
- `OtpSecondFactorStore` gains a required atomic `incrementAttempts(pendingToken) → number | null`.
- Every attempt counter (these, `PendingMultiFactorStore.recordFailedAttempt` and `AccountLockoutStore.registerAttempt`) must be one atomic increment.

`./sql`'s and the memory stores' counters already were atomic. The `KeyValueStore` defaults now run `EmailOtpStore.incrementAttempts` and `PendingMultiFactorStore.recordFailedAttempt` under a per-store semaphore, which makes them atomic within one process. The OTP and pending multi-factor conformance suites gain concurrent-count cases.
