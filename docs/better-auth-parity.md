# Better Auth Parity Plan

Status: §2 is the decided target architecture (rev 4, 2026-08-30: authorization decisions settled).

Goal: make effect-auth a suitable replacement for [Better Auth](https://www.better-auth.com/) —
and beyond that, a **batteries-included auth library**: authorization (RBAC, ABAC,
Cedar-style policies) as a first-class pillar alongside authentication, not an
afterthought (§2.5).

This document used to also hold the 2026-08-30 audit (§1), the issue triage (§3), the gap
inventory versus Better Auth (§4) and the M0–M7 roadmap (§5). Those milestones have landed, so
the sections were removed; open work is tracked in the issue tracker (framework guides and a
schema-generation CLI: #261), and the deliberate deferrals in §2.4 stand. Section numbers are
kept because source comments cite §2.5.

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
| `packages/sql`                     | Store layers over `effect/sql` (driver-agnostic)                                    | core; SQL drivers as peers                                          |
| `packages/alchemy` _(reinstated)_  | Alchemy v2 infra resources + Cloudflare D1 storage layers                           | core; `alchemy` as optional peer                                    |
| `packages/argon2` _(new, extract)_ | `PasswordHasher` layer over `@node-rs/argon2` (native dep moves out of core)        | core; `@node-rs/argon2`                                             |
| `packages/drizzle` _(M6, #171)_    | `SessionStore`/`UserStore` (+ rest) via Drizzle                                     | core; `drizzle-orm` as peer                                         |
| `packages/<email>` _(M6)_          | `EmailSender` adapters — first candidates: Resend, SES, Nodemailer                  | core; provider SDK                                                  |
| `packages/<sms>` _(M6)_            | `SmsSender` adapters — first candidate: Twilio                                      | core; provider SDK                                                  |

Consequences for the current tree:

- Core source moves from the repo root `src/` back to `packages/effect-auth/src`,
  retiring the `packages/effect-auth/dist` symlink shim. The workspace root becomes a
  plain monorepo root again.
- Two current core dependencies violate the effect-only rule:
  - `@node-rs/argon2` (native): extract to `packages/argon2`. `PasswordHasher` is
    already the service seam, so this is a layer move; core's default remains
    PBKDF2-SHA256 via `node:crypto`/WebCrypto (`PlatformCrypto`), which runs on edge
    runtimes where native modules don't.
  - The third-party Oslo WebAuthn package (pure JS, MIT): **removed**. Wholesale
    vendoring was assessed and rejected — the package is not standalone, its
    closure spans five sibling packages (asn1, binary, cbor, crypto, encoding;
    several thousand lines including crypto primitives). Instead effect-auth
    reimplements only the parsing subset it actually used, in
    `multifactor/WebAuthnCodec.ts`: a definite-length CBOR decoder, COSE
    public-key handling (ES256/RS256/EdDSA), `clientDataJSON`, authenticator
    data, and attestation objects — roughly 600 lines with no crypto
    primitives of its own (SHA-256 comes from `Cipher.ts`, signature
    verification from `node:crypto`). Core's runtime dependency list is now
    `effect` only, with no exceptions.

### 2.2 Delivery seams: unified `EmailSender` / `SmsSender` services

Today every feature takes its own delivery callback (`EmailVerification.sendEmail`,
`MagicLink.sendMagicLink`, `EmailOtp.sendVerificationOtp`, `PhoneOtp.sendOtp`). That's
fine for BYO, but gives adapter packages no single contract to implement. Add core
`EmailSender` and `SmsSender` `Context.Service` contracts (message = recipient +
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
2. **HTTP is a projection, not the foundation.** The `effect/http-api`
   contract (`http/HttpApi.ts`) is derived _from_ the services; handlers only decode,
   delegate, and encode. Guardrail: no business logic in `HttpServer.ts` handlers —
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
  framework support is a docs/examples problem (M7). **Reversed for SvelteKit** ([ADR-0021](adr/0021-sveltekit-server-adapter.md),
  #200): three apps on SvelteKit each re-wrote the same `handle` hook and form-action glue,
  and the copies drifted, so `packages/sveltekit` now ships them. Other frameworks stay deferred.

### 2.5 Authorization as a first-class pillar

Decision: effect-auth is a batteries-included **auth** library — authorization is a
core pillar, not a bolt-on. Better Auth's authorization story is thin (per-plugin
permission maps in admin/organization); this is where we leapfrog rather than chase
parity. The design draws on Lucas Barake's Effect authorization work — the composable
policy system ([video](https://www.youtube.com/watch?v=6IaEhu8epnA), article
"Building a Composable Policy System in TypeScript with Effect") and schema-embedded
ABAC ([video](https://www.youtube.com/watch?v=fKtpZ7STRKc), "Schemas are more than
just validators").

**What existed before the kernel** (then the `src/authz/` cluster): `PermissionRef`
(`resource:action` with wildcard matching), `RoleStore` + in-memory RBAC, and an
`AuthorizationPolicy` service with combinators (`allOf`/`anyOf`/`not`/`fromPredicate`,
`requirePermission`, `allowAll`/`denyAll`). A solid RBAC seed — but checks were
service-method calls, there was no reusable policy _value_, no resource/attribute
model, no policies-as-data, and the Organization plugin ran its own parallel
role→permission map (#78). That flat path is now removed and `Rbac` compiles into the
kernel instead ([ADR 0018](adr/0018-one-authorization-kernel.md)).

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

1. **Entity model (Cedar-shaped, Schema-declared).** The core authorization vocabulary is
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
   `protectedField(schema, policy)` for field-level decode/encode redaction,
   derived viewer projections applied at the HTTP boundary, and write-side schemas
   that reject fields the principal may not set. `protectedField` accepts **any**
   `Policy`; a field rule becomes tenant-editable by using a declarative policy
   that references a named action resolved through the store — opting into the data
   plane field-by-field, no special mechanism. Schema embedding is one projection of
   the same policies: everything remains usable imperatively (`Policy.enforce`/
   `Policy.check`), at the HTTP layer (route/group policies on `HttpApiMiddleware`),
   and eventually as client-side `check` hints.
7. **Release mechanics.** The authorization rework is a breaking change; it ships **in
   the same single breaking release as the M2 identifier epic** (one migration
   guide, coherent User/entity model), per the repo's clean-break convention.

The kernel evolves what exists today: `Policy<E, R>` values pulling the principal
from #94's middleware context, deny as a typed `AuthorizationDeniedError` with the
decision trace; constructors `Policy.make`/`Policy.permission`/`Policy.role`/
`Policy.action`; combinators `Policy.all`/`any`/`not`/`when`. Integration points:
org-scoped policy resolution replaces the Organization plugin's parallel role map
(#78); Admin and ApiKey permissions unify onto the same `PermissionRef`/`Policy`
model.
