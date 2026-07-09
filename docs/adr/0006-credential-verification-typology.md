# Credential/Verification typology

We organise every entity in effect-auth under a single principle borrowed from cryptography: the
**key–signature duality**, generalised. Every authentication mechanism pairs a _persistent,
registered_ thing (the credential) with a _single-use, ephemeral_ artifact whose successful
consumption proves possession or control of that credential — or of some flow's integrity. That
pair is structural, not optional.

The library has exactly three top-level categories:

1. **Credentials** — persistent registered facts that authenticate or modify authentication.
   - _Primary_ (sufficient alone): `Account`, `Passkey`, `ApiKey`.
   - _Secondary_ (modify a primary sign-in): `TwoFactorEnrollment`, `TrustedDevice`.
2. **Verifications** — single-use artifacts whose consumption proves something.
   - _Issued-on-demand, user-facing_: `EmailVerificationToken`, `PasswordResetToken`, `MagicLink`,
     `EmailOtp`, `PhoneOtp`, `OneTimeToken`.
   - _Pre-issued, user-facing_: `BackupCode`.
   - _System-internal_: `OAuthState`, `WebAuthnChallenge`.
3. **Auth state** — record of having authenticated.
   - _Stateful_: `Session`.
   - _Stateless_: `Jwt`.

The placement rule this gives us: ask first what _role_ the entity plays (which of the three
categories), then ask whether its shape can be shared with anything already in that category. If
yes, share an entity (that's how `Account` covers password and every OAuth provider). If no, give
it its own entity in the same category (that's how `Passkey` sits beside `Account`).

`BackupCode` placement is the case that decided the typology: it's stored long-term, but each row
is single-use and its consumption proves the user has the recovery list. Under the duality lens
that's a Verification, not a Credential — so it sits beside the magic-link tokens, not next to
the TOTP secret it backs up. ADR-0004's hash-at-rest rule applies to it as a Verification.

The duality also resolves the `MagicLink` question: it's a Verification of email-channel control,
the same machinery as `EmailVerificationToken`; what differs is the terminal action on consume
(create a Session, vs. set `User.emailVerified`).

**Explicit out-of-typology list** (to prevent drift): User attributes (`email`, `emailVerified`,
`isAnonymous`, `image`, `name`); the Organization domain (`Organization`, `Member`, `Team`,
`Invitation` — those are _authorization_, a separate bounded context); system infrastructure (JWT
signing keys, rate-limit storage, hasher state, OAuth provider client secrets); RBAC data
(Role definitions, Permission grants).

The trade-off: any taxonomy can be argued with at the edges (TrustedDevice as a "negative
modifier" rather than a Credential; BackupCode's long-term storage versus single-use semantics).
We accept the imprecision because the duality lens is durable — it tells you where new features
go without re-deriving the answer each time — and the alternatives we tried (five categories with
`ProtocolState`; four with mixed channel-vs-internal verifications) added structure without
adding clarity.
