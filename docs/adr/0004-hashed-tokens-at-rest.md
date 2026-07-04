# Hash all single-use tokens at rest

Following Oslo's guidance, every single-use token effect-auth issues (email verification, password
reset, magic link, email/phone OTP, API key, one-time token) is stored as an HMAC-SHA-256 (or
SHA-256, where no per-deployment secret is configured) of the token, **not as plaintext**. The
plaintext value is returned to the issuer once at creation time so it can be delivered to the user;
the store only ever holds the hash. Verification is by re-hashing the submitted value and
performing a timing-safe comparison.

The trade-off: a leaked database now leaks only hashes, not live tokens. The cost is that
operators cannot inspect or recover tokens from the store; that's the point. This applies
uniformly across all token-bearing feature entities (`EmailVerificationToken`,
`PasswordResetToken`, `MagicLink`, `EmailOtp`, `PhoneOtp`, `ApiKey`, `OneTimeToken`). Token
*Account* fields holding upstream OAuth `accessToken`/`refreshToken` are outside this rule — those
need to remain usable against the upstream provider; they are encrypted-at-rest concerns, not
hashing concerns.
