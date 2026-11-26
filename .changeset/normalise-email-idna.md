---
"@thomasfosterau/effect-auth": minor
---

Email addresses are now normalised under IDNA before they are stored or compared. `normalizeEmail` still trims the address and lower-cases the local part, and now also NFC-normalises the local part and converts the domain to punycode (UTS 46 / IDNA 2008, through the WHATWG URL host parser every runtime ships). So `bob@exämple.com`, the same address with a decomposed `ä`, `bob@EXÄMPLE.com` and `bob@xn--exmple-cua.com` are one identifier, full-width domain letters map to ASCII, and an internationalised domain stays distinct from its ASCII look-alike. A domain the parser refuses is lower-cased and NFC-normalised instead, so it still compares exactly. The new `normalizeDomain` export does the domain half. Every flow that stores or looks up an email goes through it, including SSO and Google One Tap sign-in, Cloudflare Access, SCIM, `POST /email-verifications`, and the SSO and organization domains, which now match an email's punycoded domain.

**Migrating stored identifiers.** A printable-ASCII address normalises exactly as before, so only stored values with a non-ASCII character can change, and until they are rewritten their owners cannot sign in with them. Before deploying:

1. Find the email identifiers with a non-ASCII character. On `./sql`, PostgreSQL: `SELECT id, user_id, value FROM auth_identifiers WHERE type = 'email' AND value ~ '[^ -~]'`; SQLite and D1: `... AND value GLOB '*[^ -~]*'`. Other stores: scan `type = 'email'` values the same way.
2. For each, compute `normalizeEmail(value)` in application code. When no other identifier holds the result, `UPDATE auth_identifiers SET value = <result> WHERE id = <id>`.
3. When another identifier already holds the result, two accounts were registered under spellings of one address, which this change exists to stop. Don't rewrite either automatically: keep the verified (or older) one, and settle the other with its owner.
4. Do the same for other stored addresses and domains you keep beyond `auth_identifiers`: pending organization invitations (`Invitation.email`), SSO provider `domain`s and organization domain claims. Magic links, email OTPs and email verifications expire on their own; for a rewritten address, the email-OTP failure budget (`auth_email_otp_failures`) and the per-recipient send cap start again.
