# Account unified; verification per-feature

We adopt three canonical entities from better-auth: **User**, **Session**, **Account**. `User`
has first-class `email` and `emailVerified` fields. `Account` unifies the email+password credential
(as `providerId: "credential"`, with a `password` field) and every social/OAuth link into one
record type — there is no separate `OAuthAccount`. This collapses `Credentials`,
`UserStore.getCredentials => hash`, and `OAuthAccount` into the single `Account` entity. Stores
stay interface-based, so effect-auth remains storage-agnostic — we own the entity shape, not the
database.

We deliberately **do not** unify verification into a single generic table the way better-auth
does. Each token-based feature owns its own entity and store: `EmailVerificationToken`,
`PasswordResetToken`, `MagicLink`, `EmailOtp`, `PhoneOtp`. Reasons: (1) the type system enforces
purpose at every boundary — a leaked magic-link token cannot be replayed as a password reset by a
forgetful caller; (2) per-feature entities can carry purpose-specific fields naturally (a phone
OTP has `phoneNumber`, not `email`); (3) features can evolve their token shape independently.

The trade-off: we lose better-auth's "one verification table" simplicity and the trivial migration
path between schemas. We accept this because the type-level safety and per-feature evolution beat
the marginal saving of one shared store interface — and because the existing effect-auth code is
already organised around per-feature stores, so this preserves continuity.

The schema-compat path on the `account` side is preserved; the verification side diverges
intentionally.
