---
"@thomasfosterau/effect-auth": minor
"@thomasfosterau/effect-auth-alchemy-cloudflare": patch
"@thomasfosterau/effect-auth-alchemy-postgres": patch
---

`purgeExpired` (`./sql`, and the Alchemy packages' `purgeExpired` through it) now deletes every expiring row, not only magic links, email OTPs and rate limits: expired sessions, OAuth states, WebAuthn challenges, pending second factors, email verifications and password resets, ended or idle account-lockout counters, and email-OTP failure budgets 25 hours after their latest wrong code. `PurgeExpiredResult` reports each table, and `purgeExpiredWith` takes `accountLockoutRetention` and `otpFailureRetention`. `migrate` adds the expiry indexes and an `auth_account_lockout_attempts` table, which `registerAttempt` now writes.

`purgeExpiredKV` covers every `*StoreKV` prefix the same way (`purgeExpiredKVWith` takes `otpFailureRetention`), and removes a purged token from its user's index. Expiring KV records are written in an expiry envelope, and `RateLimitStoreKV.set` keeps an entry for the TTL it is given. Records written before this read as before.

`memoryAccountLockoutStore`, `memorySamlReplayStore` and `AnonymousService`'s record of completed links now drop their spent entries as they grow, so none grows without bound.
