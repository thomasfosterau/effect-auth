# Batteries-included auth framework, not a headless toolkit

**Supersedes [ADR-0001](0001-headless-toolkit-not-framework-instance.md) and
[ADR-0003](0003-protocol-server-plugins-out-of-scope.md).**

ADR-0001 scoped effect-auth as a toolkit of composable Effect primitives with "no central instance,
no plugin runtime, no auto-mounted HTTP routes, no shipped client, no framework integrations, no
schema-migration CLI, and no cookie/CSRF helpers", and ADR-0003 followed from it, scoping out the
protocol-server tier — OIDC Provider, OAuth 2.1 Provider, SSO, SCIM, MCP Provider, Device
Authorization — on the grounds that an endpoint-shaped plugin delivers about a tenth of its value as
headless logic. Both are written in the present tense as live decisions, and the tree has since
contradicted them. `packages/effect-auth/src/http/` serves the whole surface as a typed
`effect/unstable/httpapi` contract with session cookies and trusted-origin CSRF checks;
`@thomasfosterau/effect-auth-client` is a shipped typed client; the React, Svelte, Vue and Solid
packages are framework integrations; and `OidcProvider.ts`, `Sso.ts`, `Scim.ts`,
`DeviceAuthorization.ts` and `@thomasfosterau/effect-auth-saml` are the protocol-server tier,
shipped and tested. ADR-0003 named its own reversal condition — "if a future ADR ever reverses
ADR-0001 and reintroduces an optional HTTP edge layer, the protocol-server tier becomes worth
revisiting". That reversal happened in code with no ADR recording it, so a reader following the ADRs
got an actively wrong account of the library. This record is the missing one.

**effect-auth is a batteries-included authentication and authorization framework**: a headless core,
plus an optional HTTP edge, a typed client, framework bindings, and protocol servers. The tiers are
additive and individually opt-in — by import, by layer, by package — so the core keeps what ADR-0001
was actually protecting: no `betterAuth()`-style central instance, storage-agnostic stores, plain
Services and Layers, and a consumer who assembles their own app. What ADR-0001 got wrong was not the
core's shape but the inference drawn from it — that owning an HTTP edge, a client or a protocol
server would compromise that shape. It does not, as long as each tier is entered deliberately. The
rule that keeps this true is mechanical: importing the package root for `SessionService` must not
require `effect/unstable/httpapi` or anything else the edge depends on. Where the barrel does drag
the edge in, that is a defect against this ADR, not an exception to it.

Two consequences for how "parity" is read. ADR-0001's closing line — "match functionality" means
capability parity at the server-logic layer, not surface parity at the API/HTTP/client layer — no
longer holds: there is a deliberate surface here, and it is measured as one. It is still not a clone
of better-auth's routes, and route-for-route equivalence is not the goal; the included HTTP API is
ours, and its settled wire format is JSON:API (see [docs/BOUNDARY.md](../BOUNDARY.md)). And
ADR-0003's split between "protocol servers" and "token primitives" stops being a scope boundary and
becomes a packaging one: JWT, API key, one-time token and bearer validation remain small headless
surfaces useful without any routing, while the protocol servers are a tier a consumer opts into.
Nothing in ADR-0003's reasoning about the two tiers' _shapes_ was wrong; only its conclusion that
one of them should not exist here.

The alternative considered was re-narrowing — keeping the ADR-0001 and ADR-0003 boundary honest by
splitting the protocol-server tier out of this repository, leaving a smaller core-plus-edge story
behind. Rejected. It repackages surface that already ships, is tested, and is documented, for no
behavioural gain to any consumer; it scatters the feature list that makes the library adoptable, so
that a reader asking "does this do SSO, SCIM, OIDC?" has to assemble the answer across publishing
units before they can evaluate it at all; and it re-imposes exactly the versioning and changeset
overhead ADR-0008 already declined for the organization domain, for a weaker reason. The cost we
accept instead is a large catalogue and a large API surface. The mitigations are structural —
per-tier packages, feature-local entities and opt-in-by-import (ADR-0015) — not a shorter list.

Where effect-auth sits relative to its sibling libraries, effect-jsonapi and legation, and the
dependency rules that follow from it, are stated once in [docs/BOUNDARY.md](../BOUNDARY.md). That
statement lives outside the ADR log because these records are frozen at their date, whereas the
boundary is a standing contract that all three repositories' READMEs link to.
