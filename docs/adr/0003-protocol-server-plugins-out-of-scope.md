# Protocol-server plugins out of scope; token primitives in

Given the headless boundary (ADR-0001), better-auth plugins whose entire purpose is to expose a
standardized protocol _endpoint_ deliver ~10% of their value as headless logic. We scope them out
for now: **OIDC Provider**, **OAuth 2.1 Provider**, **SSO** (SAML/OIDC consumer), **SCIM**, **MCP
Provider**, **Device Authorization** grant.

We keep the reusable token/crypto primitives that are useful in any Effect app independent of
routing: **JWT** (sign/verify, JWKS), **API key**, **One-Time Token**, **Bearer** (token
validation). These have small, headless surfaces and broad utility — the cost/value math is the
inverse of the protocol-server tier.

This is the "for now" decision. If a future ADR ever reverses ADR-0001 and reintroduces an
optional HTTP edge layer, the protocol-server tier becomes worth revisiting. Until then, treating
them as out of scope keeps the catalog focused on capabilities that genuinely benefit from being
headless primitives.
