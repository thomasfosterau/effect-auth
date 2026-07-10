# Effect Auth

A headless, storage-agnostic toolkit of composable Effect primitives for authentication and
authorization. It aims to match the _capabilities_ of better-auth while staying a library of
pieces you assemble yourself — not a configured server instance.

Every entity in this library belongs to exactly one of three categories, organised by the
**key–signature duality**: a persistent registered Credential, paired with a single-use ephemeral
Verification whose consumption proves possession or control of it; an authenticated party then
holds Auth state. See ADR-0006 for the full rationale.

## Authentication language

### User

**User**:
A person with an identity in the system, holding `email` and `emailVerified` as first-class
fields (not buried in opaque attributes). A User authenticates by presenting a Credential with a
matching Verification.
_Avoid_: Customer, member, profile.

### Credentials — _persistent registered means of authenticating_

#### Primary Credentials (sufficient alone)

**Account**:
A record linking a User to a single authentication **Provider**. Covers both the built-in
`credential` provider (where the hashed password lives on the Account) and every social/OAuth
provider. One User may have many Accounts.
_Avoid_: OAuthAccount, social account, identity, connection — these all collapse into Account.

**Passkey**:
A WebAuthn credential registered to a User — public key, counter, transports, friendly name. Its
field shape is disjoint from Account, so it lives as its own entity rather than being squeezed
into Account as another `providerId`.
_Avoid_: WebAuthnAccount, FIDOCredential when referring to the stored record.

**APIKey**:
A bearer-style credential for programmatic clients. The hashed key value is the verifier; the
plaintext is shown once at creation. Has its own scopes/permissions.
_Avoid_: AccessToken (that's the OAuth-provider-issued token on an Account), Token.

#### Secondary Credentials (modify a primary sign-in)

**TwoFactorEnrollment**:
A User's stored TOTP/HOTP secret. **Not** an Account — 2FA is a second factor, not a primary
credential.
_Avoid_: TwoFactorAccount, OTPAccount, "TOTP credential."

**TrustedDevice**:
A device on which a User has completed 2FA, allowing the prompt to be skipped for a configured
window. A _negative_ sign-in modifier (skip a factor) — still a Credential because it's a
long-lived registered fact about the User's auth setup.
_Avoid_: putting trusted-device state in Session attributes.

### Verifications — _single-use artifacts proving possession or control_

Every Verification stores its value as a hash (ADR-0004). The plaintext is delivered once and
never persisted.

#### Issued-on-demand, user-facing

**EmailVerificationToken**: single-use token confirming control of an email address.
**PasswordResetToken**: single-use token authorising a password reset for a known User.
**MagicLink**: single-use token whose consumption creates a Session — same channel-verification
mechanism as `EmailVerificationToken`, different terminal action.
**EmailOTP**: short numeric code delivered by email for sign-in or step-up.
**PhoneOTP**: short numeric code delivered by SMS for phone verification or step-up.
**OneTimeToken**: generic single-use token for ad-hoc flows.

#### Pre-issued, user-facing

**BackupCode**:
A single recovery code, hashed at rest, one row per code. Issued in batch at 2FA enrollment;
consumed by deletion on first use. Sits in Verifications (not Factors) because each code is
single-use — the "credential" being backed up is the `TwoFactorEnrollment` it accompanies.
_Avoid_: storing codes as a JSON array on the enrollment record.

#### System-internal

**OAuthState**: single-use anti-CSRF artifact tying a callback to the redirect that initiated it.
Never seen by the user — round-tripped via redirect.
**WebAuthnChallenge**: single-use freshness proof for a WebAuthn assertion. Server-side only.

### Auth state — _record of having authenticated_

**Session**: stateful auth state — a server-stored row with active and idle expiry, identified
by a secure random id.
**JWT**: stateless auth state — issued to a holder, verified by signature against JWKS, no
server-side row.

### Feature-local state entities — _opt-in entities augmenting a canonical entity with feature state_

Per ADR-0015, opt-in feature state lives in its own entity with its own store rather than as a
column on the canonical entity. Don't provide the store → don't get the feature.

**AnonymousMarker**: marks a User as anonymous (signed up without a Credential). Presence of a row
means "this User is anonymous"; conversion to a real user is its deletion plus addition of a
Credential.

**LastLoginRecord**: tracks which method (`"credential"`, `"google"`, `"passkey"`, …) was used for
this User's most recent successful sign-in. Updated best-effort and asynchronously on sign-in.
One row per User.

### Supporting terms

**Provider**:
The source that vouches for a Credential on an Account. The built-in `credential` provider is
email+password; social Providers are Google, GitHub, etc.

**Credential** vs **`credential`**:
_Capitalised_ is the category (any entity in the Credentials section above).
_Lowercase_ is the providerId string for the email+password Account.

## Organization language

A separate bounded context: organisations, membership, and managed identity. Out of the
authentication credential/verification typology (these entities are authorisation and
multi-tenancy concerns), but ships in the same package — see ADR-0008 for why.

### Organization entities

**Organization**:
A workspace, tenant, or team-as-a-billing-unit. The thing a Member belongs to and an owned User
belongs to. Stable id, name, slug, optional logo and metadata.
_Avoid_: Workspace, Tenant. "Team" is _not_ a synonym — a Team is a sub-grouping **within** an
Organization (see below).

**Member**:
The User-to-Organization relationship, carrying a `role: string` that names one of the configured
RoleDefinitions. The same User may hold Memberships in many Organizations; at most one Membership
per (User, Organization) pair.
_Avoid_: saying "the org's users" when you mean Member records — a Member is the relationship,
not a User. Also avoid "the user's org" — a User may have many Memberships.

**Invitation**:
A pending request to join an Organization, addressed to an email. A _Verification_ entity (see
the Verifications section above) with extra fields `organizationId`, `invitedEmail`,
`proposedRole`, `inviterUserId`. Hashed at rest per ADR-0004; consumed by acceptance which
creates the `Member` row.
_Avoid_: treating Invitation as separate machinery from other Verifications — same shape, same
hashing rule.

**ActiveOrgSelection**:
A pointer from a Session to the Organization the user is currently working in. Independent
entity by default; configurable to live on `Session.attributes` (see ADR-0009).
_Avoid_: putting active-org state on Session by default.

**Team**:
A sub-grouping of Members **within** an Organization, supporting a single-parent tree
hierarchy (`parentTeamId?`). Bounded depth (default 8, configurable). Cycle-free by library
enforcement. See ADR-0016.
_Avoid_: using "Team" interchangeably with "Organization" — they are nested concepts, not
synonyms.

**TeamMembership**:
The Member-to-Team relationship. Joined to `Member`, not `User` directly — being on a Team
requires being a Member of the Team's Organization. Explicit per node: being on a parent Team
does _not_ implicitly add you to its sub-Teams.
_Avoid_: implying that parent-team membership cascades to children.

### Role and permission terms

**RoleDefinition**:
A configured name + a PermissionStatement. Defined globally per `OrganizationService` at config
time; not stored per-Org. The reserved name `"owner"` always exists with default wildcard
permissions.
_Avoid_: per-org role storage (deferred feature; ADR-0009).

**PermissionStatement**:
`Record<resource, readonly action[]>` describing which actions on which resources a role permits.
Permission checks intersect a _required_ statement against the role's statement.
_Avoid_: free-form permission strings; the resource/action structure is required.

### Ownership

**Ownership**:
An Organization can own a `User` (workspace identity, full admin rights, transitively covers
Accounts) or an `Account` (managed credential, scoped to that Account). Both are optional
(`ownedByOrganizationId?: string`) and exclusive (one owner per entity). See ADR-0010 for
precedence and cascade rules.

**Owned User**:
A User whose `ownedByOrganizationId` is set. Automatically a Member of the owning Organization;
cannot self-release by default.

**Owned Account**:
An Account whose `ownedByOrganizationId` is set. The owning Org has admin rights over that
credential but not over the User. Does not imply Membership.

## Admin language

A separate bounded context: system-wide administrative operations on Users, Sessions, and
Accounts. Lives in its own subdirectory under the `effect-auth` package (ADR-0014). Out of the
authentication credential/verification typology — same as Organization.

**Ban**:
A feature-local entity marking a User as banned. `{ userId, reason, expiresAt? }`. Presence
prevents sign-in; deletion (or `expiresAt` passing) restores it. Per ADR-0015, not a column on
User.
_Avoid_: putting `bannedAt` / `banReason` on the User row.

**System-admin role**:
The reserved role string `"system-admin"`, anchoring `AdminAccessControl.requireSystemAdmin`. The
role-to-user resolution flows through the existing `AuthorizationPolicy`/`RoleStore`; the library
doesn't dictate how membership in the role is stored.
_Avoid_: hardcoding a single admin User; the role is a check, not an identity.

**Impersonation**:
The state where a system-admin is signed in _as_ a target User for support purposes. Carried as
`Session.impersonatedBy: string` (the admin's userId). A security-critical signal that lives on
Session by exception to ADR-0015 — see ADR-0014.

## Out of typology

Things that look like they belong in the typology but don't. Don't add them.

- **Foundational User fields** (`email`, `emailVerified`, `createdAt`, `image`, `name`) —
  properties of the User, not entities. Feature flags like "is anonymous" or "is banned" do _not_
  live here per ADR-0015 — they get their own entities (`AnonymousMarker`, `Ban`).
- **Organization domain entities** are _authorization_ — a separate bounded context with its own
  glossary section above. They are explicitly out of the _credential/verification typology_: when
  someone asks "which of the three categories does Organization go in?" the answer is "none, it's
  a different context."
- **System infrastructure** (JWT signing keys, rate-limit storage, hasher state, OAuth provider
  client secrets).
- **RBAC data** (Role definitions, Permission grants) — also authorization.

## Flagged ambiguities

- **"Account"** previously meant only OAuth links (`OAuthAccount`). It now also holds the password
  credential. When someone says "account," confirm they mean the unified record, not just social.
- **"Credentials"** was overloaded: a `Credentials` type _and_ a `getCredentials => hash` method.
  Both are deprecated in favour of the `password` field on a credential Account.
- **"Verification"** is a category, not a single entity. better-auth has one `verification` table;
  effect-auth has one entity _per_ token-based feature. If someone says "the verification table,"
  ask which token type they mean.
- **"Factor"** covers both positive modifiers (require an additional code) and negative modifiers
  (`TrustedDevice` — skip a factor on this device). MFA literature uses the term that way.
- **"Owner"** is both a Member role string (`Member.role === "owner"`) and a verb describing the
  ownership relationship ("the org owns this user"). Confirm which sense is meant — a sole-owner
  rule violation and an ownership-release operation are very different things.
- **"Member"** is the relationship record, not the User. "Add a member" means "create a Member
  row," not "create a User." Worth pinning when discussing flows that create or destroy these.

## Example dialogue

> **Dev:** A user signs up with email and password — does that create a User and nothing else?
>
> **Domain:** It creates a User _and_ an Account with `providerId: "credential"`, with the hashed
> password on that Account. The email isn't verified yet.
>
> **Dev:** So when they later "sign in with Google," that's a second Account on the same User?
>
> **Domain:** Right — same User, a second Account with `providerId: "google"`. Linking accounts
> just means attaching another Account row to an existing User.
>
> **Dev:** And the password-reset email and the email-verification email — different stores?
>
> **Domain:** Yes — separate entities. A reset writes a `PasswordResetToken`; an email
> verification writes an `EmailVerificationToken`. Both are Verifications, both hashed at rest,
> but distinct types so a reset token can't be replayed as a magic link.
>
> **Dev:** Where does a passkey go — Account or something else?
>
> **Domain:** A `Passkey` entity of its own. It's a primary Credential, like Account — but its
> shape (public key, counter, transports) is disjoint from Account's password/OAuth shape, so
> they're siblings in the same category, not the same table.
>
> **Dev:** And backup codes for 2FA — those live with the TOTP secret?
>
> **Domain:** No. The TOTP secret is a Credential (`TwoFactorEnrollment`); the backup codes are
> Verifications. Each `BackupCode` is single-use — consuming one is a row delete. The codes
> _back up_ the TOTP credential, but they're not credentials themselves.
>
> **Dev:** If I add a user to an organisation, do I get a new User?
>
> **Domain:** No — you create a `Member` row connecting the existing User to the Organization.
> A User can hold Memberships in many Organizations.
>
> **Dev:** And if the Organization "owns" the User?
>
> **Domain:** Then `User.ownedByOrganizationId` points to that Org, and the User is automatically
> a Member of it. The Org can delete the User; the User can't unilaterally leave by default. If
> instead the Org owns only one of the User's Accounts (`Account.ownedByOrganizationId`), the Org
> can revoke that credential but can't touch the User — a managed credential on a personal User.
