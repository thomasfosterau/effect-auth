# Second-factor entities are separate from Account

`Account` unifies *primary* credentials — the things a user signs in with — covering the
`credential` provider (email+password) and every social/OAuth provider. **Second factors do not
live on Account.** TOTP/HOTP enrolment lives in `TwoFactorEnrollment`, recovery codes in
`BackupCode` (one row per code, hashed at rest, deleted on consume), and trusted-device state in
`TrustedDevice` (independent of Session, so it survives sign-out).

The trade-off: we lose a tempting uniformity (every credential = one Account row with a
`providerId`), and we add three new entities/stores. We accept this because (1) a second factor
has different semantics from a primary credential — it modifies a sign-in rather than initiating
one, and you cannot recover an account with only a TOTP — and (2) the field shapes are disjoint
(secret/algorithm vs password/accessToken/refreshToken). Forcing 2FA onto Account bloats Account
with optional columns and obscures the abstraction. The granular `BackupCode`-per-row and
independent `TrustedDevice` table also avoid read-modify-write races on JSON arrays and let
"forget all trusted devices" be a single delete.

The principle this sets: **primary credentials → Account; second factors → feature-local
entities.** (See ADR-0006 for the refined typology this principle slots into.)
