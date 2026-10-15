# Acting as an OAuth provider for MCP clients

Model Context Protocol clients authenticate against a remote MCP server with plain OAuth 2.1: they discover the authorization server, **register themselves** (RFC 7591 dynamic client registration), then run an authorization-code flow with PKCE. Nobody hand-registers a `client_id` — an MCP client that cannot register itself cannot connect at all.

`effect-auth`'s OIDC provider covers that shape end to end. This guide wires it up and then walks a client through the three calls it makes.

## 1. Configure the provider

`mcpProviderPreset` returns the `OidcProviderConfig` slice MCP clients need: PKCE required of every client, dynamic registration on, and the RFC 7592 management endpoints available so a client can maintain its own registration.

```ts
import { Layer, Redacted } from "effect";
import { ClientIP, OidcProviderService, mcpProviderPreset } from "@thomasfosterau/effect-auth";

const oidc = OidcProviderService.layer(
  mcpProviderPreset({
    // The external base URL the auth handler is mounted at. Every advertised
    // endpoint is derived from it, and it is the `iss` claim of every id_token.
    issuer: "https://mcp.example.com/api/auth",
    loginPage: "https://mcp.example.com/login",
    consentPage: "https://mcp.example.com/consent",
    dynamicRegistration: {
      // Optional guardrails — see §4.
      initialAccessToken: Redacted.make(process.env["MCP_REGISTRATION_TOKEN"]!),
      // The address source the registration rate limit keys on: the same
      // `trustedProxy` the app passes to `Http.make` or `Http.makeAsync` (see §4).
      trustedProxy: ClientIP.cloudflare,
    },
  }),
).pipe(Layer.provide(oidcStores));
```

Everything the preset sets is overridable; `dynamicRegistration` is merged field by field, so adding a `policy` does not drop the preset's other defaults. To enable registration without the preset, set `dynamicRegistration` on your own `OidcProviderConfig` — the field's presence is what mounts the endpoints. Leaving it out keeps `POST /register` answering `404`, which is the default.

## 2. What the server exposes

Relative to the auth mount prefix (`/api/auth` above):

| Endpoint                                      | Purpose                                                |
| --------------------------------------------- | ------------------------------------------------------ |
| `GET /.well-known/oauth-authorization-server` | RFC 8414 metadata — what MCP clients fetch first       |
| `GET /.well-known/openid-configuration`       | OIDC discovery (a superset of the above)               |
| `POST /register`                              | RFC 7591 dynamic client registration                   |
| `GET`/`PUT`/`DELETE /register/:clientId`      | RFC 7592 registration management                       |
| `GET /oauth2/authorize`                       | Authorization endpoint (`code`, PKCE `S256`)           |
| `POST /oauth2/token`                          | Token endpoint (`authorization_code`, `refresh_token`) |
| `GET /oauth2/userinfo`                        | Standard claims for a bearer access token              |
| `GET /.well-known/jwks.json`                  | Keys that verify the `id_token`                        |

The metadata document advertises exactly what the provider implements:

```json
{
  "issuer": "https://mcp.example.com/api/auth",
  "authorization_endpoint": "https://mcp.example.com/api/auth/oauth2/authorize",
  "token_endpoint": "https://mcp.example.com/api/auth/oauth2/token",
  "registration_endpoint": "https://mcp.example.com/api/auth/register",
  "jwks_uri": "https://mcp.example.com/api/auth/.well-known/jwks.json",
  "scopes_supported": ["openid", "profile", "email", "offline_access"],
  "response_types_supported": ["code"],
  "grant_types_supported": ["authorization_code", "refresh_token"],
  "token_endpoint_auth_methods_supported": ["client_secret_basic", "client_secret_post", "none"],
  "code_challenge_methods_supported": ["S256"]
}
```

`registration_endpoint` points at `/register` only while dynamic registration is enabled; otherwise it names the admin-gated `/oauth2/register`, which is all the provider has to offer.

## 3. The client's three calls

### Register

An MCP client is a public client: it ships no secret, so it registers with `token_endpoint_auth_method: "none"` and authenticates at the token endpoint with its PKCE verifier instead.

```http
POST /api/auth/register
Content-Type: application/json

{
  "redirect_uris": ["http://127.0.0.1:33418/callback"],
  "token_endpoint_auth_method": "none",
  "grant_types": ["authorization_code", "refresh_token"],
  "response_types": ["code"],
  "client_name": "Example MCP Client",
  "scope": "openid profile email offline_access"
}
```

```http
201 Created

{
  "client_id": "6f1c…",
  "client_id_issued_at": 1756512000,
  "client_name": "Example MCP Client",
  "redirect_uris": ["http://127.0.0.1:33418/callback"],
  "grant_types": ["authorization_code", "refresh_token"],
  "response_types": ["code"],
  "token_endpoint_auth_method": "none",
  "scope": "openid profile email offline_access",
  "registration_access_token": "…",
  "registration_client_uri": "https://mcp.example.com/api/auth/register/6f1c…"
}
```

Notes that matter in practice:

- **Redirect URIs** must be `https`, or loopback `http` on `127.0.0.1`/`[::1]`/ `localhost` (RFC 8252 §7.3) — a loopback URI is exactly what a desktop MCP client wants. A private-use scheme such as `myapp://callback` is rejected unless the deployment opts in with `dynamicRegistration.allowedRedirectUriSchemes: ["myapp"]`. Fragments are always rejected (RFC 6749 §3.1.2).
- **Unknown members** (`client_uri`, `logo_uri`, `contacts`, `software_id`, …) are accepted and ignored, as RFC 7591 §2 requires.
- **Omitting `token_endpoint_auth_method`** means `client_secret_basic` per the RFC, and the response then carries a one-time `client_secret` (with `client_secret_expires_at: 0` — secrets do not expire).
- The client is held to what it registered: the authorization endpoint rejects scopes outside its `scope`, and the token endpoint refuses a grant outside its `grant_types` with `unauthorized_client`.
- `registration_access_token` and `client_secret` are returned **once**. Both are stored as sha256 digests and cannot be read back.

Rejections use the RFC 7591 §3.2.2 body:

```http
400 Bad Request

{ "error": "invalid_redirect_uri", "error_description": "…" }
```

### Authorize (PKCE `S256`)

The client generates a verifier, sends its `S256` challenge, and opens the URL in a browser. An unauthenticated visitor is bounced to `loginPage` with the original URL in `redirect_to`; a first-time client shows `consentPage`.

```
GET /api/auth/oauth2/authorize
  ?response_type=code
  &client_id=6f1c…
  &redirect_uri=http://127.0.0.1:33418/callback
  &scope=openid%20profile%20email%20offline_access
  &state=<random>
  &code_challenge=<BASE64URL(SHA256(verifier))>
  &code_challenge_method=S256
```

PKCE is not optional here: a public client that omits `code_challenge` is redirected back with `error=invalid_request`, and `code_challenge_method=plain` is refused. The success case is a `302` to `http://127.0.0.1:33418/callback?code=…&state=…`.

### Token

```http
POST /api/auth/oauth2/token
Content-Type: application/x-www-form-urlencoded

grant_type=authorization_code
&code=…
&redirect_uri=http://127.0.0.1:33418/callback
&code_verifier=<the verifier>
&client_id=6f1c…
```

```json
{
  "access_token": "…",
  "token_type": "Bearer",
  "expires_in": 3600,
  "refresh_token": "…",
  "id_token": "…",
  "scope": "openid profile email offline_access"
}
```

The `refresh_token` is present because the grant included `offline_access`; refresh tokens rotate on every use, and replaying a consumed one revokes the whole family. The `id_token` verifies against `/.well-known/jwks.json`, and the access token resolves claims at `/oauth2/userinfo`.

Errors follow RFC 6749: `invalid_client` is a `401`, everything else a `400` with the code in `message`.

## 4. Guardrails

Open registration means an anonymous caller can create a `client_id`. Three independent controls apply, and they compose:

**Initial access token** (RFC 7591 §3.1). Set `dynamicRegistration.initialAccessToken` to a `Redacted` secret and `POST /register` requires `Authorization: Bearer <token>`; a missing or wrong token is a `401` with `code: "invalid_token"`. For per-tenant tokens, pass a verifier instead:

```ts
dynamicRegistration: {
  initialAccessToken: (token) =>
    tenants.isValidRegistrationToken(token), // Effect<boolean, AuthError>
}
```

**Registration policy.** A hook over the _normalized_ metadata (every RFC default already applied), run after validation and before anything is written:

```ts
dynamicRegistration: {
  policy: (metadata) =>
    Effect.succeed(
      metadata.redirectUris.every((uri) => uri.startsWith("http://127.0.0.1"))
        ? { allow: true, skipConsent: false }
        : { allow: false, errorDescription: "Loopback redirect URIs only" },
    ),
}
```

Returning `false` (or `allow: false`) answers `400 invalid_client_metadata`, which is the only refusal RFC 7591 §3.2.2 defines. When the refusal is about the _caller_ rather than the metadata, name it explicitly: `{ allow: false, error: "access_denied" }` answers `403`. An accepting disposition may also carry `skipConsent` to waive the consent screen for a client the policy recognises as first-party.

**Rate limiting.** `POST /register` is limited per client IP through the usual `RateLimiter` service — 10 registrations per hour by default, tunable with `dynamicRegistration.rateLimit`. The limit needs a `RateLimiter` in the HTTP handler's `services`: without one, `Http.make` or `Http.makeAsync` fails at startup with `RateLimiterConfigError` (`make` throws it, `makeAsync` rejects with it) rather than serving registrations with the limit off (#389). The limit is keyed by client address, so the layer needs an address source at build. Set `dynamicRegistration.trustedProxy` to the source the app passes to `Http.make` or `Http.makeAsync` (for example `ClientIP.cloudflare`), or set `dynamicRegistration.allowMissingClientIp: true` to accept that address-less registrations are refused. With neither, `OidcProviderService.layer` fails at build with `ClientAddressConfigError`, before any request. The preset enables registration, so an MCP provider always needs one of the two. A registration whose client address cannot be resolved is refused with `429` rather than counted under a shared bucket. `/register` is also covered by `defaultEndpointRules` for deployments that enable `ipRateLimit`, which needs a `trustedProxy` to resolve addresses.

## 5. Managing a registration (RFC 7592)

The `registration_access_token` from step 3 authenticates three calls on `/register/:clientId`, all as `Authorization: Bearer <registration_access_token>`:

- `GET` — read the current metadata.
- `PUT` — replace it. The body is validated and policy-checked exactly as at registration. `token_endpoint_auth_method` is immutable: a public client cannot promote itself to confidential.
- `DELETE` — deregister (`204`).

A wrong token, a missing token, and an unknown `client_id` are all `401`, so the endpoint cannot be used to enumerate clients. Set `dynamicRegistration.management: false` to leave these unmounted (`404`).

Two deliberate deviations from RFC 7592 §3.1: the read response omits `client_secret` (it is stored hashed and cannot be recovered — re-register to get a new one), and `PUT` does not rotate credentials.

## 6. Storage

Dynamic registration writes through the existing `OidcClientStore` — no new store. Clients created this way carry a few extra optional fields (`registrationAccessTokenHash`, `tokenEndpointAuthMethod`, `grantTypes`, `responseTypes`, `scope`, `dynamicallyRegistered`), so a custom store implementation must round-trip them for RFC 7592 and the per-client grant/scope checks to work.
