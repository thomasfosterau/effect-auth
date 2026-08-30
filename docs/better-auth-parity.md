# Better Auth Parity Plan

Status: proposed · Date: 2026-08-30

Goal: make effect-auth a suitable replacement for [Better Auth](https://www.better-auth.com/).
This document triages the 20 open issues against the code as it stands today
(post-restructure, `3ff3bc6`), records two regressions discovered during the audit,
inventories the remaining feature gaps versus Better Auth, and lays out an ordered
roadmap.

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

## 2. Issue triage

Verified against the current tree (`src/`, `packages/client/`). "Close after
verification" means the feature is present; run the issue's acceptance criteria as a
checklist, add any missing test, then close.

| Issue | Subject                                             | Observed state                                                                                                                                                                                                                    | Action                                                                                      |
| ----- | --------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------- |
| #66   | Session `updateAge`, `rememberMe`, config semantics | `updateAge` throttle in `session/SessionService.ts:133-136`; `rememberMe` threaded through Types → HTTP schemas → server                                                                                                          | Close after verification                                                                    |
| #68   | Account-linking guard + controls                    | Landed in `78e377f`; `trustedProviders`/`allowDifferentEmails`/`updateUserInfoOnLink`/`LastCredential` in `oauth/OAuth.ts`                                                                                                        | Close after verification                                                                    |
| #73   | **Identifier epic**                                 | Phase 1 only: `Identifier.ts` + KV store exist, but `EmailPassword` still keys on `getUserByEmail`, `User` still requires `email`/`emailVerified`. `docs/PLAN.md` holds the phase plan — which references the deleted SQL package | **Open — the core-model milestone (M2)**                                                    |
| #74   | Trusted devices + email/SMS OTP factor              | `session/TrustedDevice.ts` (config-gated, signed, `Config` integration) + `secondfactor/OTPSecondFactor.ts` with gate layers                                                                                                      | Close after verification                                                                    |
| #75   | **SAML SSO + SCIM**                                 | Not started; `SSO.ts` is OIDC-only                                                                                                                                                                                                | **Open — enterprise milestone (M4)**                                                        |
| #76   | Bearer-token issuance                               | `set-auth-token` handling in `http/HTTPServer.ts` (+ tests)                                                                                                                                                                       | Close after verification                                                                    |
| #77   | OIDC DCR + MCP                                      | DCR done (`registerClient`, `registration_endpoint` advertised). No `.well-known/oauth-authorization-server`, no MCP preset                                                                                                       | **Part 2 open (M4)**                                                                        |
| #78   | **Org teams + dynamic access control**              | Not started; no `Team` in `Organization.ts`, roles still config-static                                                                                                                                                            | **Open (M3)**                                                                               |
| #83   | OTel spans                                          | `Observability.ts`, `Effect.withSpan` across 9 modules, `Effect.fn` naming throughout, `docs/OBSERVABILITY.md`                                                                                                                    | Close after a coverage/redaction check                                                      |
| #84   | One-time token module                               | `OneTimeToken.ts` incl. `redeemOneTimeTokenForSession`                                                                                                                                                                            | Close after verification                                                                    |
| #85   | AuthLifecycle bypasses/atomicity                    | All four FIXes visible in `AuthLifecycle.ts` (consumes app `EmailPasswordService`, email-match on verify, peek/burn token ordering, resend on unverified)                                                                         | Close after verification                                                                    |
| #88   | OIDC provider hardening                             | Refresh `familyId` + `absoluteExpiresAt` + family revocation, `prompt=none` handling present                                                                                                                                      | Verify residuals (scope down-scoping on refresh, registration scheme allowlist), then close |
| #91   | `@effect-auth/sql` correctness                      | **Moot — package deleted.** Findings (orDie gets, non-atomic upserts, rate-limit undercount) must be re-applied when the SQL adapter is restored                                                                                  | Fold into M1/M5; update issue                                                               |
| #92   | Client lifecycle & parity                           | Focus/visibility refresh, `BroadcastChannel` cross-tab sync, plugin mechanism, Vue warn+`dispose()` all present                                                                                                                   | Verify endpoint coverage breadth; note the React regression is separate (M0)                |
| #94   | HttpApiMiddleware / CurrentUser                     | `http/HTTPMiddleware.ts` with `CurrentUser`/`CurrentSession` + tests                                                                                                                                                              | Close after verification                                                                    |
| #95   | Redacted + Config                                   | `Redacted` in 18 modules (incl. OAuth `clientSecret`), `Config`-based construction in OAuth/JWT/MultiFactor/TrustedDevice/SessionCookieCache                                                                                      | Sweep for stragglers, then close                                                            |
| #111  | **AccountLockout hardening**                        | **Not done.** Store contract still `get`/`set`/`delete` (`plugins/AccountLockout.ts:35-40`): no atomic increment, no second dimension, no isolation/fail-open decision                                                            | **Open (M1)**                                                                               |
| #116  | HTTP boundary hardening                             | `__Host-` default-when-secure, generic 500 bodies, `maxBodySize` (64 KiB default), `Referer` fallback, out-of-prefix 404 — all present                                                                                            | Close after verification                                                                    |
| #117  | Device authorization hardening                      | Atomic consume in store contract, `user_code` rate limit (`USER_CODE_RATE_LIMIT`), `slow_down` escalation without window reset                                                                                                    | Close after verification                                                                    |
| #171  | Drizzle adapter                                     | Not started; depends on the storage-adapter decision below                                                                                                                                                                        | **Open (M5)**                                                                               |

## 3. Regressions to repair (M0)

1. **Restore the SQL storage story.** The last version of `packages/sql` lives at
   `abd5d13^`. It predates the restructure (old naming, old store contracts, `email`
   column model), so restoration means porting to the current API, not a straight
   revert. Re-apply #91's correctness findings (atomic `UPDATE … SET count = count+1`,
   `ON CONFLICT` upserts, `AuthError` instead of `orDie`, preserved `cause`) as part of
   the port — cheaper than porting the bugs and fixing them later. Decide `@effect-auth/alchemy`'s
   fate at the same time (restore, or drop and delete its README/docs references).
   Until restored, the only persistence path is BYO stores or
   `KeyValueStores` over `KeyValueStore.layerSql` — well short of Better Auth's adapter story.
2. **Restore the React client binding.** Last version at `f219705^`
   (`packages/client/src/react.ts`); port to the current `Client.ts` store API. Until
   then, either ship it or drop the `./react` export + keyword so the package isn't
   advertising a module that 404s.
3. **Make the docs true again.** `README.md`'s package table and
   `docs/PLAN.md`/`KeyValueStores.ts` references to `@effect-auth/sql` describe a
   package that isn't in the tree; reconcile once decision 1 lands.
4. **Close the done issues** (per the table above) so the tracker reflects reality —
   each close is a quick acceptance-criteria pass and possibly one added test.

## 4. Gap inventory vs Better Auth

Feature-by-feature, beyond what the issues already track. ✓ = at or beyond parity.

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

| Gap                               | Better Auth has                                                    | effect-auth today                                                                          | Plan                                                                                  |
| --------------------------------- | ------------------------------------------------------------------ | ------------------------------------------------------------------------------------------ | ------------------------------------------------------------------------------------- |
| Database adapters                 | Drizzle/Prisma/Kysely/Mongo adapters + CLI schema generate/migrate | Nothing in-tree (post-regression); KV layers + BYO stores                                  | M0 restore SQL pkg; M5 Drizzle (#171); CLI/migration story a stretch goal             |
| Surrogate-key identity            | Flexible via `additionalFields`; but BA also hardwires email       | Email hardwired in `User`; phase 1 of #73 done                                             | M2 — also a differentiator, not just parity                                           |
| Org teams + dynamic AC            | `teams`, `createAccessControl` runtime roles                       | Static config roles, no teams                                                              | M3 (#78)                                                                              |
| SAML SSO                          | SSO plugin supports SAML                                           | OIDC only                                                                                  | M4 (#75)                                                                              |
| SCIM provisioning                 | Enterprise provisioning                                            | Absent                                                                                     | M4 (#75)                                                                              |
| MCP auth server preset            | `mcp` plugin                                                       | OIDC provider + DCR exist; no `.well-known/oauth-authorization-server`, no preset          | M4 (#77.2) — small delta                                                              |
| Client endpoint coverage          | Full inference via plugins                                         | Plugin mechanism exists; first-party coverage still partial (~26 of ~80 endpoints wrapped) | M6 (#92.2) — ship first-party plugins per feature area                                |
| React/Solid client hooks          | React, Vue, Svelte, Solid                                          | Vanilla, Vue, Svelte (React regressed)                                                     | M0 restores React; Solid optional                                                     |
| Social provider breadth           | ~25 presets                                                        | 4 presets (Google/GitHub/Discord/Microsoft) + Apple secret helper + custom config          | M6 — cheap, add top ~8 (Apple, Facebook, X, LinkedIn, GitLab, Slack, Spotify, Twitch) |
| Framework guides                  | Next/Nuxt/SvelteKit/Astro/Hono/Express integrations                | One mountable Web handler (covers all of them technically); few guides                     | M6 — docs/examples, not code                                                          |
| Payments plugins (Stripe/Polar/…) | Yes                                                                | No                                                                                         | Recommend **out of scope** for core; revisit as community adapters                    |
| Sign in with Ethereum             | `siwe` plugin                                                      | No                                                                                         | Recommend out of scope initially                                                      |

## 5. Roadmap

Ordering is dependency-driven: the SQL restore (M0) unblocks the identifier epic's
storage phases; the identifier model (M2) unblocks SCIM/SAML provisioning and cleans
up org invitations; teams (M3) unblock SCIM groups.

- **M0 — Repair & truth (small, do first).** Restore/port `@effect-auth/sql` (with
  #91's fixes baked in) and `client/react.ts`; decide alchemy; fix README/docs; close
  the ~12 verified-done issues.
- **M1 — Security close-out (small).** #111 lockout hardening (atomic increment on the
  store contract, isolate the reset tap, second dimension or documented tradeoff,
  fail-open decision); verify the #88/#116/#117 residuals.
- **M2 — Identifier epic (large, breaking).** Execute `docs/PLAN.md` phases 2–8 on the
  restored SQL package: surrogate-keyed `User`, email/username/phone as `Identifier`s,
  migrate EmailPassword/Username/PhoneOTP/OAuth-linking/Anonymous/Admin/Org flows,
  ship as the breaking release with a migration guide.
- **M3 — Organization parity (medium).** #78 teams + dynamic per-org roles, on top of
  the identifier model.
- **M4 — Enterprise & MCP (large).** #75 SAML (signature verification is the critical
  path — pick the XML-DSig approach deliberately) and SCIM 2.0 (maps onto identifiers
  - teams); #77.2 MCP preset (`.well-known/oauth-authorization-server` + a thin config
    over the existing provider) — do MCP first, it's days not weeks.
- **M5 — Adapter ecosystem (medium).** #171 Drizzle adapter per its captured spec
  (decide: wrap the SQL stores vs standalone); document the BYO-store contract as the
  Prisma/Kysely answer; evaluate a schema-generation CLI.
- **M6 — DX & breadth (ongoing).** Client endpoint-coverage plugins + 2FA-challenge
  continuation helper (#92.2), more social presets, framework guides/examples.

After M0–M1 the library is an honest Better Auth replacement for non-enterprise apps
whose stores it ships or that bring their own; M2–M4 close the enterprise gap and pull
ahead of Better Auth on the identity model; M5–M6 close the onboarding/DX gap that
drives most real-world adoption decisions.
