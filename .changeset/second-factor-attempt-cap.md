---
"@thomasfosterau/effect-auth": minor
---

**Security — a pending second-factor challenge accepts at most 5 wrong codes (#496).** `MultiFactorService.verifyTotp` and `verifyBackupCode` used to accept wrong codes against one challenge until it expired, capped only by the HTTP layer's per-address rate limit. Wrong TOTP and backup codes now count against the challenge together, and the attempt that reaches `MultiFactorConfig.maxFailedAttempts` (default 5) deletes it. That attempt, and every later one against the same token, answers as a wrong code does (`MultiFactorError` with the method's "Invalid multi-factor code" / "Invalid backup code" message), so a caller cannot tell a capped challenge from a wrong code. An unknown challenge token now answers the same way, where it used to say "Invalid or expired multi-factor challenge token"; an expired one still says it has expired.

**Breaking — `PendingMultiFactorStore` has a new required member,** `recordFailedAttempt(token): Effect<number, AuthError>`, which counts one wrong code against an existing challenge and resolves to the count so far; `delete` now also drops the count. `PendingMultiFactorStoreKV` keeps the count in the challenge's record (read-modify-write, like the KV store's other counters). New conformance suite: `Testing.pendingMultiFactorStoreConformance`.

effect-auth/sql adds the `auth_pending_multi_factor_attempts` table (`migrate` creates it; a table of its own because SQLite has no idempotent `ADD COLUMN`). `recordFailedAttempt` is one `INSERT … SELECT … ON CONFLICT … DO UPDATE … RETURNING`, and `delete` removes the challenge before its count. effect-auth/client's `./testing` fixture implements the new member.
