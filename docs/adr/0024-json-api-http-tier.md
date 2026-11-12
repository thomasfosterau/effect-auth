# The HTTP tier is JSON:API, except the RFC tier

**Extends [ADR-0017](0017-batteries-included-auth-framework.md)**, which settled that the included
HTTP API's wire format is JSON:API without recording what that covers. ADR-0001 had said "no
auto-mounted HTTP routes"; this record describes the furthest thing from it, a complete HTTP API
with one wire format, and the one place that format stops.

Until #205 the HTTP tier was 124 endpoints in one `effect/http-api` group, in a dialect of its own:
command routes (`POST /sign-in`, `POST /organization/set-active`, `POST /admin/users/list`), plain
JSON bodies, and tagged-error bodies. The conversion ran in six slices (#494, #495, #498, then the
organization, team and admin slices) and is complete. What it left is two kinds of endpoint, and the
line between them is not a matter of taste.

## Decision

1. **Every endpoint this library designs is a JSON:API resource operation**, built on
   effect-jsonapi's `Resource`, `Endpoint` and `Group` and declared once in `Http.Resources`. It
   takes and answers `application/vnd.api+json`, fails with a JSON:API error document, and runs
   the protocol middleware (content negotiation, schema errors). An imperative operation is
   modelled as a resource with a lifecycle even when that resource exists only to be created once:
   signing in creates a `sessions` resource, a ban is a `user-bans` resource, a device approval is
   a `device-authorizations/decisions` create. Secret tokens (reset, verification, second-factor,
   device user codes) travel in a request body, never in a URL.
2. **Every endpoint whose wire format another specification fixes keeps that format**: the RFC
   8628 device grant's device side (`/device/code`, `/device/token`), OAuth 2.0 and OIDC Core
   (`/oauth2/authorize`, `/oauth2/consent`, `/oauth2/token`, `/oauth2/userinfo`), RFC 7591 / 7592
   dynamic registration (`/register`, `/register/:clientId`), OIDC Discovery and RFC 8414
   (`/.well-known/openid-configuration`, `/.well-known/oauth-authorization-server`), RFC 7517
   (`/jwks`, `/.well-known/jwks.json`), the SSO bindings (`/sso/callback`, the SAML ACS and SP
   metadata), and SCIM 2.0 (`/scim/v2/*`, `application/scim+json`). This is the **RFC tier**: the
   `auth` and `scim` groups of the contract. It is not a compromise or an unfinished part of the
   conversion. A client built to RFC 8628, an OAuth library, an IdP posting a SAML form or a SCIM
   provisioner will not accept a JSON:API document, so converting one of these breaks every
   conforming peer.
3. **The line is tested, not remembered.** `OpenApi.test.ts` checks that every resource group
   declares `application/vnd.api+json` for every body it takes or answers and that no RFC-tier
   operation declares it, and that the RFC tier is exactly the list above. Each RFC-tier suite pins
   its endpoints' media types and that their bodies carry none of a JSON:API document's top-level
   members. `client/ClientRoutes.test.ts` checks that the browser client names only operations the
   contract serves.
4. **The RFC tier is described by its specification, not by this library.** Where an endpoint
   departs from the letter of its specification, the departure is documented on the endpoint (the
   device grant's members are camelCase, and its approved poll issues a session rather than an
   access token) and fixed there, never by moving it into the resource tier.

Where one feature spans both tiers, the split follows the caller. A first-party app administers
OIDC clients through `oauth-clients` (JSON:API, admin-gated), while an OAuth client registers
itself at `/register` (RFC 7591); the provider's discovery documents name `/register` as
`registration_endpoint` only while dynamic registration is enabled, and never the resource
registry. The device's own endpoints are RFC 8628; the verification page the signed-in user opens
answers through `device-authorizations`, because RFC 8628 §3.3 leaves that page to the server.

## Consequences

- JSON:API error documents (`status`, `detail`, `meta.message`, `meta.code`) for the resources;
  the RFC tier keeps its own refusals: RFC 7591's `error` and `error_description` for
  registration, SCIM error resources for SCIM, and the grant's or RFC 6749's error code as the
  `message` of the device and token endpoints' `400`s.
- The headless core is unaffected: none of this is reachable from the package root
  (`ModuleGraph.test.ts`), and effect-jsonapi stays an optional peer of `./http` alone.
- The conversion broke the store contract once, where an item URL needed an id the stores did not
  keep: `OrganizationStore.getMemberById`, ids on `TeamMember` and `OrgRole`, `getTeamMemberById`,
  `getOrgRoleById`, and `addTeamMember(record)`. A resource is otherwise addressed by an id the
  stores already held.
- [docs/guides/jsonapi-migration.md](../guides/jsonapi-migration.md) maps every removed route to
  its replacement; the core README's endpoint reference lists both tiers.
