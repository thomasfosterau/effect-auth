---
"@thomasfosterau/effect-auth": patch
---

The JSON:API conversion of the HTTP tier is complete (#205, slice 6). Every endpoint effect-auth designs is a JSON:API resource operation; the endpoints whose wire format another specification fixes (RFC 8628's `/device/code` and `/device/token`, OAuth 2.0 / OIDC's `/oauth2/*`, RFC 7591 / 7592's `/register`, RFC 8414 and OIDC discovery, the JWKS, the SSO callbacks and SAML metadata, and SCIM 2.0) keep it as the RFC tier, recorded in [ADR-0024](https://github.com/thomasfosterau/effect-auth/blob/trunk/docs/adr/0024-json-api-http-tier.md). No endpoint's behaviour changes in this release.

- **Migration guide:** [docs/guides/jsonapi-migration.md](https://github.com/thomasfosterau/effect-auth/blob/trunk/docs/guides/jsonapi-migration.md) maps every removed route to its replacement in one table, with the store-contract changes (`getMemberById`, `getTeamMemberById`, `getOrgRoleById`, the `TeamMember` and `OrgRole` ids, `addTeamMember(record)`), the client method changes and the status-code changes.
- **Endpoint reference:** the README's "HTTP endpoint reference" lists the JSON:API resources and the RFC tier, each RFC endpoint with its specification and wire format.
- The doc comments on the `./http` groups (`Http.sessionsGroup`, `Http.adminUsersGroup`, `Http.impersonationsGroup`, `Http.oauthClientsGroup`, `Http.ssoProvidersGroup`, `Http.ssoAuthorizationsGroup`, `Http.tokensGroup`, `Http.deviceAuthorizationsGroup`) no longer name the routes they replaced.
- The RFC tier is pinned by tests: the OpenAPI document declares `application/vnd.api+json` on every resource group and on no RFC-tier endpoint, each RFC endpoint's media type is checked on the wire, and the browser client may call only routes the contract serves.
