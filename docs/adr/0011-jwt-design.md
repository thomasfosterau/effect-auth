# JWT design

The `Jwt` module signs and verifies bearer tokens; it does not own the HTTP edge (ADR-0001) or
the signing keys (ADR-0006 puts those in "system infrastructure"). Six decisions shape it.

**Default algorithm: ES256**, with `RS256` and `EdDSA` selectable via config. ES256 hits the
sweet spot for modern headless services — small JWKS, fast verify, mature client support. RS256
remains the option for compatibility with legacy IdPs and older Java clients; EdDSA is offered
for deployments standardising on Ed25519.

**Keys are consumer-managed via a `JwkStore` interface.** The library ships an in-memory reference
implementation for tests and dev; production deployments back the store with their own secret
manager (Vault, KMS, sealed env vars). The library never persists private keys on its own. This
matches ADR-0001's "we don't own infrastructure" line and avoids shipping a half-real-half-fake
key store that nobody can safely use in production.

**Key rotation is kid-based from day one.** The `JwkStore` may hold multiple keys; one is
designated active for signing, and the JWT header carries the active key's `kid`. Verification
selects the key whose `kid` matches the inbound token. Rotation = generate a new active key,
demote the previous one to verify-only, retire it after its longest-lived token has expired.
Single-active-key rotation was considered and rejected: it makes rotation a downtime event for
any in-flight tokens.

**JWKS publication is pure data.** The library exposes `getJwks(): Effect<Jwks, ..., JwkStore>`
returning the public-key set in JWKS format. Consumers mount whatever endpoint they want
(typically `/.well-known/jwks.json`). The library doesn't mount routes.

**Custom claims are typed via `Schema`.** `issueJwt` is parameterised over a Schema describing the
custom-claims shape; standard claims (`iss`, `sub`, `aud`, `exp`, `iat`, `nbf`, `jti`) are
populated by the library. `verifyJwt` returns a parsed-typed claims object on success. This
matches the rest of effect-auth's idiom (Schema for input/output types).

**JWT is issued from a Session by default; no separate refresh-token entity.** The signing
function takes a `sessionId`, validates the Session, then signs a short-lived JWT (default 15
minutes) carrying the User identity and configured custom claims. Refresh = re-call
`issueJwtFromSession` while the Session is still valid; the Session itself is the long-lived
auth state. This composes with the existing Session machinery and matches better-auth's plugin
behaviour.

The trade-off: JWT-only deployments that don't want a Session machinery (classic OAuth-bearer
microservices) have to wait — we'll add `issueJwtStandalone` if real demand appears. We accept
this because shipping both shapes from day one doubles the documentation and test surface for a
feature whose primary use case (services that can't share the session cookie) is exactly the
Session-derived case. Revocation lag is the standard JWT trade-off and is bounded by the chosen
TTL.
