# SCIM 2.0 provisioning

Enterprise SSO answers "may this person sign in?". SCIM answers the other half: "who exists, and who left?". An identity provider — Okta, Entra ID, OneLogin — pushes user and group lifecycle into your directory over a small REST API, so somebody deprovisioned in the IdP stops being able to sign in immediately rather than whenever their session happens to expire.

`effect-auth` implements the RFC 7643 resources and the RFC 7644 protocol as a projection of the core model. Nothing new is stored: SCIM `User`s are `User` records plus their email `Identifier`s, and SCIM `Group`s are organization teams.

## 1. Wire up the service

SCIM needs a connection store, a slice of user persistence, and the identifier, organization and session services it projects onto.

```ts
import { Layer } from "effect";
import {
  ScimService,
  ScimConnectionStore,
  ScimUserStore,
  memoryScimConnectionStore,
} from "@thomasfosterau/effect-auth/Scim";

const scimStores = Layer.mergeAll(
  Layer.succeed(ScimConnectionStore)(memoryScimConnectionStore()), // swap for SQL
  Layer.succeed(ScimUserStore)(yourUserStore),
  identifierStoreLayer,
  organizationStoreLayer,
  // The organization's verified domains: SCIM claims addresses only on them.
  organizationDomainStoreLayer,
  sessionServiceLayer,
);

const scim = ScimService.layer({
  // The externally-visible URL the endpoints are mounted at, used to build each
  // resource's `meta.location` so the IdP can follow what it is handed.
  baseUrl: "https://app.example.com/api/auth/scim/v2",
  // Organization role granted to users the IdP provisions, for every
  // connection. Omit it to let each organization's own `defaultRole` decide
  // (itself defaulting to "member").
  defaultRole: "member",
  // Page-size cap, advertised as `filter.maxResults`. Default 100.
  maxPageSize: 100,
}).pipe(Layer.provide(scimStores));
```

Merge `scim` into the layer you hand `Http.make`. Until you do, every SCIM route answers `404` — the same 404-until-configured rule the rest of the optional modules follow.

`ScimUserStore` is a three-method contract (`create` / `get` / `update`) over the same `User` table everything else uses; declaring its own tag follows the convention `OAuthUserStore`, `MagicLinkUserStore` and `AdminUserStore` already set.

`create` resolves to `Auth.UserStore.CreateUserResult`, `{ user, created }`. Report `created: true` only for a user this call inserted. A store that returns a user who already existed reports `created: false`, and provisioning then answers `409` (`uniqueness`) without writing to that user: no identifier, no organization membership. When the user already exists, `create` must not modify that row either: use a plain `INSERT` and let the unique index on the address fail, or `INSERT … ON CONFLICT DO NOTHING` followed by a select (If that select finds no row (for example under a REPEATABLE READ snapshot that predates the conflicting insert), fail with `AuthError` rather than return an invented user.), never `ON CONFLICT DO UPDATE` ([BYO stores](./byo-stores.md) has the full contract).

## 2. Mint a connection

A **connection is per organization**: it is one tenant's provisioning credential, and everything it can read or write is scoped to that organization's members and teams.

```ts
const { connection, token } = yield * scimService.createConnection(organizationId);
```

`token` is the bearer secret the IdP will present. It exists in plaintext exactly once — only its SHA-256 digest is stored — so show it to the administrator and forget it. Gate this behind an organization-admin check in your own admin UI; the SCIM endpoints themselves never mint tokens.

`revokeConnection(id)` kills it instantly, and `listConnections(orgId)` shows an operator which integrations exist and when each last called (`lastUsedAt`).

## 3. What the IdP talks to

Relative to the auth mount prefix (`/api/auth` in the example above):

| Endpoint                                                  | Purpose                                   |
| --------------------------------------------------------- | ----------------------------------------- |
| `GET /scim/v2/ServiceProviderConfig`                      | What this server supports                 |
| `GET /scim/v2/ResourceTypes`                              | `User` and `Group`                        |
| `GET /scim/v2/Schemas`                                    | The attributes of each                    |
| `POST /scim/v2/Users`                                     | Provision a user (`201`)                  |
| `GET /scim/v2/Users`                                      | List / filter / paginate                  |
| `GET /scim/v2/Users/:id`                                  | Read one                                  |
| `PUT /scim/v2/Users/:id`                                  | Replace                                   |
| `PATCH /scim/v2/Users/:id`                                | Partial update (activate, rename, emails) |
| `DELETE /scim/v2/Users/:id`                               | **Deactivate** — a soft disable (`204`)   |
| `POST`/`GET`/`PUT`/`PATCH`/`DELETE /scim/v2/Groups[/:id]` | The same for teams                        |

Every route except the three discovery documents requires `Authorization: Bearer <provisioning token>`. A missing, malformed, or unknown token gets the same `401`, so a caller cannot probe which tokens exist. Bodies are `application/scim+json` in both directions.

The three discovery documents are unauthenticated: they describe the server, not any tenant's data.

## 4. The mapping

| SCIM                | effect-auth                                |
| ------------------- | ------------------------------------------ |
| `User.id`           | `User.id` (the surrogate key, verbatim)    |
| `User.userName`     | the primary email `Identifier`'s value     |
| `User.emails[]`     | the user's `email` identifiers             |
| `User.displayName`  | `User.name`                                |
| `User.active`       | NOT `attributes.scimDeactivated`           |
| `User.externalId`   | `attributes.scimExternalId`                |
| `Group`             | an organization `Team`                     |
| `Group.displayName` | `Team.name`                                |
| `Group.members[]`   | team members (`value` is the core user id) |

Users provisioned here get their email identifier **verified**: the IdP is the system of record for that address, the same attestation an OIDC `email_verified` claim or a signed SAML assertion carries. That means a SCIM-provisioned user can immediately complete an SSO sign-in without a verification round trip.

Which email is "primary" is pinned in `attributes.scimUserName`. Without it, a `PATCH` of `userName` would be silently overtaken by an older secondary address the next time the resource was read, because the primary is otherwise the earliest verified email. For a user SCIM did not create, the fallback is exactly that earliest-verified rule, so an account that signed up directly still projects correctly.

## 5. Managed users

A connection writes only to users its organization manages: users one of the organization's SCIM connections or SSO providers created (they carry `attributes.provisionedBy`), and users whose primary email is on one of the organization's verified domain claims. Domain claims are proved through DNS or attested by the operator, so add and verify them before you hand out a token, and provide an `OrganizationDomainStore`: without one an organization manages only the users it created.

- Every address SCIM claims (`userName` on create or rename, `emails` on create, `PATCH` or `PUT`) must be on a verified domain; any other is `400 invalidValue`, and nothing is written.
- SCIM never unclaims an address off the verified domains: naming one in a `remove` is `400 invalidValue`, and a remove-all or an authoritative `PUT` leaves it.
- A member the organization does not manage (someone who signed up on another domain and joined, or another organization's user) can be read and listed, and `active` can change, but anything else (`userName`, `emails`, `displayName`, `externalId`) is `400 mutability`. A `PUT` that restates their profile unchanged may still set `active`.

## 6. Deactivation is a soft disable

For a member the organization does not manage, `active: false` and `DELETE /Users/:id` deactivate only the membership (`status: "inactive"`, the role parked in `previousRole` and restored by `active: true`), as `OrganizationService.deactivateMember` does; their account and sessions are not this tenant's. For a managed user, `PATCH {"active": false}` and `DELETE /Users/:id` both deactivate the account:

- `attributes.scimDeactivated` is set to `true`,
- every live session, API key and OIDC grant (access and refresh tokens, consents) the user holds is revoked,
- the account, its identifiers, its organization membership and its audit trail all stay put.

Reactivation (`PATCH {"active": true}`) is then a single write — which is what an IdP expects when somebody returns from leave, and what a hard delete would have made impossible.

`SessionService` refuses a deactivated user a new session and refuses any session they still present, with no plugin to wire: `validateSession` and `createSession` fail with `UserBannedError`. The OIDC provider mints no tokens for them and its userinfo endpoint refuses them. JWTs already issued cannot be revoked and run to their expiry. `ScimDeactivatedPlugin` is now a deprecated no-op.

## 7. What is deliberately not supported

SCIM is a large specification and most of it is optional. This implementation advertises in `ServiceProviderConfig` exactly what it does, and nothing else — half-working provisioning is worse than provisioning that says no:

- **Filters**: `userName eq "…"` and `externalId eq "…"` on `/Users`, `displayName eq "…"` on `/Groups`. That is the whole of what Okta and Entra ID send. Anything else is `400 invalidFilter` rather than a silent full-directory response.
- **PATCH paths**: `replace` on `active`, `displayName`, `userName`, `externalId`; `add`/`remove` on `emails`; `add`/`remove`/`replace` on `members` (including the `members[value eq "…"]` path filter). Entra's path-less form (`{"op":"replace","value":{"active":false}}`) is expanded into the same operations, and its stringly-typed `"False"` is accepted. Anything else is `400 invalidPath`.
- **Not implemented**: bulk operations, sorting, ETags, password changes, and the enterprise user extension. All are reported as unsupported.

## 8. Errors

Failures use the RFC 7644 §3.12 error body verbatim — no extra members, because conformance suites check:

```json
{
  "schemas": ["urn:ietf:params:scim:api:messages:2.0:Error"],
  "status": "409",
  "scimType": "uniqueness",
  "detail": "The email \"ada@acme.test\" is already in use"
}
```

`409 uniqueness` is the important one: it is how an IdP learns to reconcile against an existing user instead of retrying forever. Cross-tenant reads answer `404`, not `403` — a connection for org A must not be able to use the status code to discover that a user exists in org B.
