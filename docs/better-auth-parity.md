# Better Auth Parity Plan

Status: accepted direction · Date: 2026-08-30 (rev 4: authz decisions settled)

Goal: make effect-auth a suitable replacement for [Better Auth](https://www.better-auth.com/) —
and beyond that, a **batteries-included auth library**: authorization (RBAC, ABAC,
Cedar-style policies) as a first-class pillar alongside authentication, not an
afterthought (§2.5).
This document records the target architecture (§2), triages the 20 open issues against
the code as it stands today (post-restructure, `3ff3bc6`), records two regressions
discovered during the audit, inventories the remaining feature gaps versus Better
Auth, and lays out an ordered roadmap.

## 1. Headline findings

1. **Most open issues are already implemented.** The bulk of the tracker was filed on
   2026-07-04 against the pre-restructure layout. Since then, the linking guard (#68),
   session `updateAge`/`rememberMe` (#66), trusted devices + OTP second factor (#74),
   bearer issuance (#76), one-time tokens (#84), the AuthLifecycle fixes (#85), OIDC
   refresh families + `prompt=none` (#88), client refresh/plugins (#92), the HTTP
   middleware seam (#94), `Redacted`/`Config` adoption (#95), HTTP boundary hardening
   (#116), and device-authorization hardening (#117) have all landed. They need a
   verification pass and closing, not implementation.
2. **Two silent regressions need repair.**
   - `@effect-auth/sql` and `@effect-auth/alchemy` were deleted in `abd5d13`
     ("feat: add IP rate limiting and last login method plugins" — the message never
     mentions the deletion). The repo currently ships **no SQL storage adapter**, while
     `README.md`, `docs/PLAN.md`, and issues #91/#171 still refer to `@effect-auth/sql`
     as if it exists.
   - `packages/client/src/react.ts` was deleted in `f219705` ("feat: add Argon2
     password hasher" — likewise unannounced), yet `@thomasfosterau/effect-auth-client`
     still declares a `./react` export pointing at `dist/react.js` and advertises React
     bindings in its description. The React binding is broken/missing.
3. **The genuinely open work is:** account-lockout hardening (#111), the identifier
   epic phases 2+ (#73), organization teams + dynamic access control (#78), SAML +
   SCIM (#75), the MCP provider preset (#77 part 2), the Drizzle adapter (#171), and
   the storage-adapter story generally (where #91's findings should be re-applied).

## 2. Target architecture (decided)

### 2.1 Monorepo: monolithic core + thin adapter packages

The core is deliberately a **maximal monolith**: every feature that can be built on
`effect` v4 alone lives in one package, one dependency graph, one release. Anything
that needs a third-party runtime dependency — a database driver, an ORM, an email or
SMS provider SDK, a native module, infrastructure tooling — lives in its own adapter
package that implements a core service contract.

| Package                            | Role                                                                                | Allowed dependencies                                                |
| ---------------------------------- | ----------------------------------------------------------------------------------- | ------------------------------------------------------------------- |
| `packages/effect-auth`             | The monolithic core: every service, store contract, plugin, and the HTTP projection | `effect` v4 only (+ possibly `@effect/platform-browser` — see §2.2) |
| `packages/client`                  | Vanilla typed client + React/Svelte/Vue bindings                                    | core types; frameworks as optional peers                            |
| `packages/sql`                     | Store layers over `effect/unstable/sql` (driver-agnostic)                           | core; SQL drivers as peers                                          |
| `packages/alchemy` _(reinstated)_  | Alchemy v2 infra resources + Cloudflare D1 storage layers                           | core; `alchemy` as optional peer                                    |
| `packages/argon2` _(new, extract)_ | `PasswordHasher` layer over `@node-rs/argon2` (native dep moves out of core)        | core; `@node-rs/argon2`                                             |
| `packages/drizzle` _(M6, #171)_    | `SessionStore`/`UserStore` (+ rest) via Drizzle                                     | core; `drizzle-orm` as peer                                         |
| `packages/<email>` _(M6)_          | `EmailSender` adapters — first candidates: Resend, SES, Nodemailer                  | core; provider SDK                                                  |
| `packages/<sms>` _(M6)_            | `SMSSender` adapters — first candidate: Twilio                                      | core; provider SDK                                                  |

Consequences for the current tree:

- Core source moves from the repo root `src/` back to `packages/effect-auth/src`,
  retiring the `packages/effect-auth/dist` symlink shim. The workspace root becomes a
  plain monorepo root again.
- Two current core dependencies violate the effect-only rule:
  - `@node-rs/argon2` (native): extract to `packages/argon2`. `PasswordHasher` is
    already the service seam, so this is a layer move; core's default remains
    PBKDF2-SHA256 via `node:crypto`/WebCrypto (`PlatformCrypto`), which runs on edge
    runtimes where native modules don't.
  - `@oslojs/webauthn` (pure JS, MIT): **kept as the single documented
    exception** (M0 outcome). Vendoring was assessed and rejected: the package is
    not standalone — its closure spans five `@oslojs/*` packages (asn1, binary,
    cbor, crypto, encoding, several thousand lines including crypto primitives),
    and vendoring security-critical parsing/crypto code would cut us off from
    upstream patches. WebAuthn stays in the maximal core with this one pure-JS
    dependency, re-reviewed if the rule ever needs to be absolute.

### 2.2 Delivery seams: unified `EmailSender` / `SMSSender` services

Today every feature takes its own delivery callback (`EmailVerification.sendEmail`,
`MagicLink.sendMagicLink`, `EmailOTP.sendVerificationOTP`, `PhoneOTP.sendOTP`). That's
fine for BYO, but gives adapter packages no single contract to implement. Add core
`EmailSender` and `SMSSender` `Context.Service` contracts (message = recipient +
purpose + template params), with default layers that route the existing per-feature
callbacks through them. Per-feature callbacks stay for full control; adapters
implement the unified seam once and every feature lights up.

`@effect/platform-browser` enters only if the client or WebCrypto plumbing needs it;
core's `PlatformCrypto` already abstracts `node:crypto`/WebCrypto, so treat it as
"allowed if needed", not a goal.

### 2.3 Effect-native, not an HTTP-RPC wrapper

Better Auth is architecturally an HTTP handler framework (built on better-call):
features are endpoints first, and even server-side calls go through `auth.api.*`
wrappers around those handlers. We take the opposite stance, and it should be stated
as a design rule:

1. **Services are the API.** Every feature is a `Context.Service` with a `layer`,
   fully usable in-process with no HTTP anywhere — errors in the typed error channel,
   storage/delivery as service contracts, config via `Config`/`Redacted`, tracing via
   spans. This is already true and must stay true.
2. **HTTP is a projection, not the foundation.** The `effect/unstable/httpapi`
   contract (`http/HTTPApi.ts`) is derived _from_ the services; handlers only decode,
   delegate, and encode. Guardrail: no business logic in `HTTPServer.ts` handlers —
   every endpoint must correspond to a service method callable directly.
3. **Composability over mounting.** `HttpApiMiddleware` + `CurrentUser`/
   `CurrentSession` (#94, done) is the flagship integration: consumers compose auth
   _into_ their own `HttpApi` rather than mounting a black box beside it. The mounted
   Web handler remains as the zero-effort path (and is how "framework support" works
   without framework adapters).
4. **The typed client derives from the contract**, not from stringly-typed paths —
   client plugins (#92) should build on the httpapi contract types so client and
   server can't drift.

### 2.4 Deliberate deferrals (door open, not closed)

- **Ethereum / SIWE and payments (Stripe, Polar, …):** not now. The door stays open
  structurally: each would land as `packages/<name>` implementing existing seams
  (SIWE = a sign-in service + hooks like other methods; payments = hooks/plugins on
  lifecycle events). No core changes are required to add them later, which is the
  point of the adapter architecture.
- **Framework adapters (Next/Nuxt/SvelteKit/…):** not now. The Web-standard handler
  plus `HttpApiMiddleware` already mount everywhere; if dedicated packages ever prove
  necessary they slot in as `packages/<framework>` without touching core. Until then,
  framework support is a docs/examples problem (M7).

### 2.5 Authorization as a first-class pillar

Decision: effect-auth is a batteries-included **auth** library — authorization is a
core pillar, not a bolt-on. Better Auth's authorization story is thin (per-plugin
permission maps in admin/organization); this is where we leapfrog rather than chase
parity. The design draws on Lucas Barake's Effect authorization work — the composable
policy system ([video](https://www.youtube.com/watch?v=6IaEhu8epnA), article
"Building a Composable Policy System in TypeScript with Effect") and schema-embedded
ABAC ([video](https://www.youtube.com/watch?v=fKtpZ7STRKc), "Schemas are more than
just validators").

**What exists today** (`src/authz/`): `PermissionRef` (`resource:action` with
wildcard matching), `RoleStore` + in-memory RBAC, and an `AuthorizationPolicy`
service with combinators (`allOf`/`anyOf`/`not`/`fromPredicate`, `requirePermission`,
`allowAll`/`denyAll`). A solid RBAC seed — but checks are service-method calls, there
is no reusable policy _value_, no resource/attribute model, no policies-as-data, and
the Organization plugin runs its own parallel role→permission map (#78).

**Governing principle (owner decision): Effect-native-first.** The `Policy` value is
the primary object of the whole framework — not a builder for Cedar policies. Cedar
contributes semantics adopted on their merits (reviewed against
[docs.cedarpolicy.com](https://docs.cedarpolicy.com), 2026-08-30) and, at most, a
serialization format for interop. Within the Policy universe there is a
**declarative subset** — policies built from the entity/attribute vocabulary rather
than arbitrary code — and policies in that subset get extra powers _because_ they are
data: storable, tenant-editable, validated, sliceable, and exportable. A
`Policy.custom` (arbitrary Effect predicate) is first-class everywhere policies are
accepted; it just isn't storable/analyzable, and the types make that visible.

Settled decisions (design review, 2026-08-30):

1. **Entity model (Cedar-shaped, Schema-declared).** The core authz vocabulary is
   typed entity references (`User::"id"`-style), attributes, and a parent hierarchy
   (a DAG), so RBAC (`principal in Role::"admin"`) and ReBAC are hierarchy checks.
   Entity types and per-action `appliesTo` signatures are declared with **Effect
   Schema**, which doubles as Cedar-style policy validation. Users, orgs, teams, and
   roles become entities; actions are entities too (groupable).
2. **Pure core, Effect shell.** Cedar's split, Effect-natively: `AttributeProvider`/
   `EntityStore` services resolve the entity slice (an Effect); evaluation over the
   slice is a **pure, total function**. Decisions are deterministic and replayable
   from a logged slice; slicing determines what to fetch. `Policy.custom` is the
   effectful escape hatch, marked opaque.
3. **Evaluation semantics.** Default deny; forbid overrides permit;
   order-independent; the decision carries its determining policies (the trace
   feeds audit hooks + #83 spans). **Error posture deviates from Cedar
   deliberately:** an erroring permit cannot grant, and an erroring forbid DENIES —
   fail-closed in both directions, errors recorded in the trace. (Cedar skips
   erroring policies, which fails open for forbids; the deviation is documented for
   the cedar adapter.)
4. **Canonical stored format: our own Schema-defined JSON.** The declarative subset
   serializes to an Effect Schema-validated document format owned by this library
   (validated on write, versioned). The TS eDSL and stored documents are two
   authorings of the same subset. **Cedar text/JSON are import/export formats** in
   the door-open `packages/cedar` adapter (which can also swap in cedar-wasm as an
   evaluator) — never the source of truth.
5. **Templates in v1.** The `PolicyStore` contract models Cedar-style templates
   (`?principal`/`?resource` slots) and template-linked policies from the start —
   per-instance grants ("share this doc with that user", per-tenant role
   assignment) are tiny link records, and editing a template retroactively updates
   its links. This is the mechanism org role assignment (M4) and resource sharing
   ride on.
6. **Schema-embedded authorization** (the Barake insight, generalized): Effect
   Schema transformations carry a Requirements channel, so schemas can demand the
   policy context and enforce/redact **at the data boundary** —
   `Authz.protectedField(schema, policy)` for field-level decode/encode redaction,
   derived viewer projections applied at the HTTP boundary, and write-side schemas
   that reject fields the principal may not set. `protectedField` accepts **any**
   `Policy`; a field rule becomes tenant-editable by using a declarative policy
   that references a named action resolved through the store — opting into the data
   plane field-by-field, no special mechanism. Schema embedding is one projection of
   the same policies: everything remains usable imperatively (`Policy.enforce`/
   `Policy.check`), at the HTTP layer (route/group policies on `HttpApiMiddleware`),
   and eventually as client-side `check` hints.
7. **Release mechanics.** The `authz/` rework is a breaking change; it ships **in
   the same single breaking release as the M2 identifier epic** (one migration
   guide, coherent User/entity model), per the repo's clean-break convention.

The kernel evolves what exists today: `Policy<E, R>` values pulling the principal
from #94's middleware context, deny as a typed `AuthorizationDeniedError` with the
decision trace; constructors `Policy.make`/`Policy.permission`/`Policy.role`/
`Policy.action`; combinators `Policy.all`/`any`/`not`/`when`. Integration points:
org-scoped policy resolution replaces the Organization plugin's parallel role map
(#78); Admin and APIKey permissions unify onto the same `PermissionRef`/`Policy`
model.

## 3. Issue triage

Verified against the current tree (`src/`, `packages/client/`). "Close after
verification" means the feature is present; run the issue's acceptance criteria as a
checklist, add any missing test, then close.

| Issue | Subject                                             | Observed state                                                                                                                                                                                                                    | Action                                                                                      |
| ----- | --------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------- |
| #66   | Session `updateAge`, `rememberMe`, config semantics | `updateAge` throttle in `session/SessionService.ts:133-136`; `rememberMe` threaded through Types → HTTP schemas → server                                                                                                          | Close after verification                                                                    |
| #68   | Account-linking guard + controls                    | Landed in `78e377f`; `trustedProviders`/`allowDifferentEmails`/`updateUserInfoOnLink`/`LastCredential` in `oauth/OAuth.ts`                                                                                                        | Close after verification                                                                    |
| #73   | **Identifier epic**                                 | Phase 1 only: `Identifier.ts` + KV store exist, but `EmailPassword` still keys on `getUserByEmail`, `User` still requires `email`/`emailVerified`. `docs/PLAN.md` holds the phase plan — which references the deleted SQL package | **Open — the core-model milestone (M2)**                                                    |
| #74   | Trusted devices + email/SMS OTP factor              | `session/TrustedDevice.ts` (config-gated, signed, `Config` integration) + `secondfactor/OTPSecondFactor.ts` with gate layers                                                                                                      | Close after verification                                                                    |
| #75   | **SAML SSO + SCIM**                                 | Not started; `SSO.ts` is OIDC-only                                                                                                                                                                                                | **Open — enterprise milestone (M5)**                                                        |
| #76   | Bearer-token issuance                               | `set-auth-token` handling in `http/HTTPServer.ts` (+ tests)                                                                                                                                                                       | Close after verification                                                                    |
| #77   | OIDC DCR + MCP                                      | DCR done (`registerClient`, `registration_endpoint` advertised). No `.well-known/oauth-authorization-server`, no MCP preset                                                                                                       | **Part 2 open (M5)**                                                                        |
| #78   | **Org teams + dynamic access control**              | Not started; no `Team` in `Organization.ts`, roles still config-static                                                                                                                                                            | **Open — dynamic AC lands on the policy framework (M3), teams in M4**                       |
| #83   | OTel spans                                          | `Observability.ts`, `Effect.withSpan` across 9 modules, `Effect.fn` naming throughout, `docs/OBSERVABILITY.md`                                                                                                                    | Close after a coverage/redaction check                                                      |
| #84   | One-time token module                               | `OneTimeToken.ts` incl. `redeemOneTimeTokenForSession`                                                                                                                                                                            | Close after verification                                                                    |
| #85   | AuthLifecycle bypasses/atomicity                    | All four FIXes visible in `AuthLifecycle.ts` (consumes app `EmailPasswordService`, email-match on verify, peek/burn token ordering, resend on unverified)                                                                         | Close after verification                                                                    |
| #88   | OIDC provider hardening                             | Refresh `familyId` + `absoluteExpiresAt` + family revocation, `prompt=none` handling present                                                                                                                                      | Verify residuals (scope down-scoping on refresh, registration scheme allowlist), then close |
| #91   | `@effect-auth/sql` correctness                      | **Moot — package deleted.** Findings (orDie gets, non-atomic upserts, rate-limit undercount) must be re-applied when the SQL adapter is restored                                                                                  | Fold into M0 restore; update issue                                                          |
| #92   | Client lifecycle & parity                           | Focus/visibility refresh, `BroadcastChannel` cross-tab sync, plugin mechanism, Vue warn+`dispose()` all present                                                                                                                   | Verify endpoint coverage breadth; note the React regression is separate (M0)                |
| #94   | HttpApiMiddleware / CurrentUser                     | `http/HTTPMiddleware.ts` with `CurrentUser`/`CurrentSession` + tests                                                                                                                                                              | Close after verification                                                                    |
| #95   | Redacted + Config                                   | `Redacted` in 18 modules (incl. OAuth `clientSecret`), `Config`-based construction in OAuth/JWT/MultiFactor/TrustedDevice/SessionCookieCache                                                                                      | Sweep for stragglers, then close                                                            |
| #111  | **AccountLockout hardening**                        | **Not done.** Store contract still `get`/`set`/`delete` (`plugins/AccountLockout.ts:35-40`): no atomic increment, no second dimension, no isolation/fail-open decision                                                            | **Open (M1)**                                                                               |
| #116  | HTTP boundary hardening                             | `__Host-` default-when-secure, generic 500 bodies, `maxBodySize` (64 KiB default), `Referer` fallback, out-of-prefix 404 — all present                                                                                            | Close after verification                                                                    |
| #117  | Device authorization hardening                      | Atomic consume in store contract, `user_code` rate limit (`USER_CODE_RATE_LIMIT`), `slow_down` escalation without window reset                                                                                                    | Close after verification                                                                    |
| #171  | Drizzle adapter                                     | Not started; lands as `packages/drizzle` per §2.1                                                                                                                                                                                 | **Open (M6)**                                                                               |

## 4. Gap inventory vs Better Auth

Feature-by-feature, beyond what the issues already track.

**At parity already:** email/password, email verification, password reset (+ HIBP,
captcha), magic link, email OTP, phone OTP, username, anonymous, passkeys/WebAuthn,
TOTP 2FA + backup codes + trusted devices + OTP factor, social OAuth with PKCE +
account linking controls, Google One Tap, generic/custom OAuth providers
(`OAuthProviderConfig`), session management + cookie cache + multi-session +
`rememberMe`/`updateAge`, bearer mode, JWT + JWKS, API keys, admin (ban/impersonate),
organizations (members/invitations/roles), rate limiting + account lockout (Better
Auth has no lockout plugin — an advantage), device authorization, one-time token,
OIDC provider with PKCE + DCR, OIDC-based SSO, last-login-method, OpenAPI + Scalar
reference, hooks/audit, OTel spans, typed HTTP client, `HttpApiMiddleware`
composability (an Effect-native advantage Better Auth has no equivalent of).

**Gaps, roughly in order of adoption impact:**

| Gap                               | Better Auth has                                                    | effect-auth today                                                                               | Plan                                                                                                           |
| --------------------------------- | ------------------------------------------------------------------ | ----------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------- |
| Authorization framework           | Thin: per-plugin permission maps (admin/org) only                  | RBAC seed in `authz/` (permissions, roles, combinators); no policy values/ABAC/schema embedding | M3 (§2.5) — **leapfrog, not parity**: policy kernel, ABAC, Cedar-style policies-as-data, schema-embedded authz |
| Database adapters                 | Drizzle/Prisma/Kysely/Mongo adapters + CLI schema generate/migrate | Nothing in-tree (post-regression); KV layers + BYO stores                                       | M0 restore `packages/sql`; M6 Drizzle (#171); CLI/migration story a stretch goal                               |
| Email/SMS delivery adapters       | Docs-level integrations; callbacks                                 | Per-feature callbacks only; no unified sender seam                                              | M1 `EmailSender`/`SMSSender` seams (§2.2); M6 first adapter packages                                           |
| Surrogate-key identity            | Flexible via `additionalFields`; but BA also hardwires email       | Email hardwired in `User`; phase 1 of #73 done                                                  | M2 — also a differentiator, not just parity                                                                    |
| Org teams + dynamic AC            | `teams`, `createAccessControl` runtime roles                       | Static config roles, no teams                                                                   | M3 (dynamic AC via policy framework) + M4 (teams) (#78)                                                        |
| SAML SSO                          | SSO plugin supports SAML                                           | OIDC only                                                                                       | M5 (#75)                                                                                                       |
| SCIM provisioning                 | Enterprise provisioning                                            | Absent                                                                                          | M5 (#75)                                                                                                       |
| MCP auth server preset            | `mcp` plugin                                                       | OIDC provider + DCR exist; no `.well-known/oauth-authorization-server`, no preset               | M5 (#77.2) — small delta                                                                                       |
| Client endpoint coverage          | Full inference via plugins                                         | Plugin mechanism exists; first-party coverage still partial (~26 of ~80 endpoints wrapped)      | M7 (#92.2) — first-party plugins per feature area, derived from the httpapi contract                           |
| React/Solid client hooks          | React, Vue, Svelte, Solid                                          | Vanilla, Vue, Svelte (React regressed)                                                          | M0 restores React; Solid optional                                                                              |
| Social provider breadth           | ~25 presets                                                        | 4 presets (Google/GitHub/Discord/Microsoft) + Apple secret helper + custom config               | M7 — cheap, add top ~8 (Apple, Facebook, X, LinkedIn, GitLab, Slack, Spotify, Twitch)                          |
| Framework guides                  | Next/Nuxt/SvelteKit/Astro/Hono/Express integrations                | One mountable Web handler (covers all of them technically); few guides                          | M7 — docs/examples per §2.4; dedicated adapter packages deferred                                               |
| Payments plugins (Stripe/Polar/…) | Yes                                                                | No                                                                                              | **Deferred by decision** (§2.4); door open as future adapter packages                                          |
| Sign in with Ethereum             | `siwe` plugin                                                      | No                                                                                              | **Deferred by decision** (§2.4); door open as a future adapter package                                         |

## 5. Roadmap

Ordering is dependency-driven: the monorepo restructure + SQL restore (M0) unblock
the identifier epic's storage phases; the identifier model (M2) unblocks SCIM/SAML
provisioning and cleans up org invitations; the authorization framework (M3) supplies
the engine for org dynamic access control (M4), which with teams unblocks SCIM groups
(M5).

- **M0 — Monorepo restructure & regression repair (done 2026-08-30, except the
  issue-close pass which awaits owner sign-off).**
  - Move core `src/` → `packages/effect-auth/src`; retire the dist symlink shim;
    root becomes a plain workspace.
  - Restore/port `packages/sql` from `abd5d13^` onto the current store contracts,
    with #91's fixes baked into the port (atomic `UPDATE … SET count = count + 1`,
    `ON CONFLICT` upserts, `AuthError` instead of `orDie`, preserved `cause`).
  - Reinstate `packages/alchemy` (same port treatment; `alchemy` as optional peer).
  - Restore `packages/client/src/react.ts` from `f219705^` onto the current
    `Client.ts` store API.
  - Extract `packages/argon2`; vendor `@oslojs/webauthn`; core's dependency list
    becomes `effect` only.
  - Make README/docs match the tree; close the ~12 verified-done issues.
- **M1 — Security close-out + delivery seams (done 2026-08-30).** #111 lockout
  hardening shipped (atomic `registerAttempt` on the store contract with memory/
  SQL/D1 implementations, isolated reset tap, documented DoS tradeoff with
  IPRateLimitPlugin as the second dimension, configurable fail-open/fail-closed
  on store outage); the #88/#116/#117 residuals verified as already implemented;
  `EmailSender`/`SMSSender` seams + `emailCallbacks`/`smsCallbacks` added (§2.2).
  The 14 verified-done issues are closed with evidence comments.
- **M2 — Identifier epic (done 2026-08-30; breaking, ships with M3).**
  `docs/PLAN.md` phases 2–8 executed: `User` is surrogate-keyed
  (`{id, name?, image?, createdAt, updatedAt, attributes}`), email/username/
  phone are `Identifier`s behind `IdentifierStore` (`claimIdentifier` race
  pattern, verification-as-promotion), every flow migrated
  (EmailPassword/Username/PhoneOTP/MagicLink/EmailOTP/OAuth-linking/SSO/
  GoogleOneTap/Anonymous/Admin/Org/AccountManagement/OIDC/MultiFactor), the
  HTTP contract carries derived optional `email`/`emailVerified` plus
  `GET`/`DELETE /identifiers` endpoints, sql/alchemy schemas dropped the user
  email columns, and the upgrade path is `docs/migration.md` § 9 with design
  record `DESIGN.md` § D12. Release note: held on the shared M2+M3 breaking
  release (decision 7) — do not cut until M3 lands.
- **M3 — Authorization framework (large; §2.5).** The batteries-included pillar,
  built in the layer order that keeps each stage shippable — and released **together
  with M2 as one breaking release** (decision 7):
  1. Policy kernel: `Policy` values + combinators + `enforce`/`check`, decision
     traces (default deny, forbid overrides permit, asymmetric fail-closed).
  2. Entity model: Schema-declared entity types/actions, hierarchy,
     `AttributeProvider`/`EntityStore` slice resolution; pure evaluator over the
     slice.
  3. Policies-as-data: the Schema-defined document format, `PolicyStore` with
     templates + template-linked policies; wire #78's dynamic access control onto
     it.
  4. Schema-embedded authorization: `protectedField`/viewer projections/write-side
     guards, plus route-level policies on `HttpApiMiddleware`.
- **M4 — Organization parity (medium).** #78 teams; migrate the Organization
  plugin's static role map onto the M3 policy framework (kept as the zero-config
  default).
- **M5 — Enterprise & MCP (large).** #75 SAML (signature verification is the critical
  path — pick the XML-DSig approach deliberately; if it needs a dependency, SAML
  becomes `packages/saml` per the §2.1 rule) and SCIM 2.0 (maps onto identifiers +
  teams); #77.2 MCP preset (`.well-known/oauth-authorization-server` + a thin config
  over the existing provider) — do MCP first, it's days not weeks.
- **M6 — Adapter ecosystem (medium).** `packages/drizzle` (#171, per its captured
  spec — decide: wrap the SQL stores vs standalone); first `EmailSender`/`SMSSender`
  adapter packages (Resend, Twilio); document the BYO-store contract as the
  Prisma/Kysely answer; evaluate a schema-generation CLI; door-open candidates
  (`packages/cedar`, SIWE, payments) whenever demand appears.
- **M7 — DX & breadth (ongoing).** Client endpoint-coverage plugins + 2FA-challenge
  continuation helper (#92.2), more social presets, framework guides/examples.

After M0–M1 the library is an honest Better Auth replacement for non-enterprise apps
whose stores it ships or that bring their own; M2–M3 pull ahead of Better Auth on the
identity model and authorization; M4–M5 close the enterprise gap; M6–M7 close the
onboarding/DX gap that drives most real-world adoption decisions.
