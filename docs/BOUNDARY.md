# The three-library boundary

`effect-jsonapi`, `effect-auth` and `legation` are three libraries by the same author, designed to
be usable together and easy to mistake for three layers of one product. They are not. This file is
the single statement of what each one is and how they may depend on each other. It is authored here
and linked — not restated — from the READMEs of all three repositories; if the boundary changes, it
changes here.

## The three libraries

- **[effect-jsonapi](https://github.com/thomasfosterau/effect-jsonapi)** — a faithful implementation
  of the [JSON:API v1.1](https://jsonapi.org/format/) specification on Effect. It depends on neither
  of the others. Both of the others are downstream of it.
- **[effect-auth](https://github.com/thomasfosterau/effect-auth)** — authentication and
  authorization. It **uses JSON:API for its included HTTP API**, but that HTTP API is **not a
  requirement for using the library**.
- **[legation](https://github.com/thomasfosterau/legation)** — a client-side query and mutation
  client with caching, offline support and sync, on Effect. It **requires neither of the other two**.

"Downstream" describes the direction a dependency is allowed to run, not a requirement: it means
effect-jsonapi never depends on effect-auth or legation, and never grows surface to suit them.

## What "not required" means for effect-auth

effect-auth's headless core — the stores, services, layers and free Effect functions — is the whole
library as far as a consumer is concerned. Everything above it is a tier you opt into: the included
HTTP API, the typed client, the framework bindings, the protocol servers
([ADR-0017](./adr/0017-batteries-included-auth-framework.md)). So all three of these are supported,
in any combination, and none of them is privileged:

- authenticate an application with no HTTP tier from this library at all — your routes, our
  services, and neither of the other two libraries anywhere in the tree;
- authenticate a JSON:API service, using the included HTTP API, which is itself JSON:API;
- authenticate an application built on legation, with or without the included HTTP API.

That the included HTTP API is JSON:API is a settled decision about its wire format, not a claim that
every endpoint has been converted: the conversion of the non-RFC endpoints is in progress, and the
tier whose wire format another specification mandates (the RFC 8628 device grant, the OAuth/OIDC
token, authorization and `userinfo` endpoints, RFC 8414 metadata, RFC 7591/7592 registration, JWKS,
SCIM) stays as those specifications require.

Mechanically, "not required" means that importing the package root must not pull the HTTP tier — or,
through it, effect-jsonapi — into a consumer's module graph. A consumer who wants `SessionService`
and nothing else must not be made to install or bundle the thing we have just said is optional.

## The dependency rules

1. **effect-auth may depend on effect-jsonapi**, in any package here. The included HTTP API is
   JSON:API, so this edge is expected rather than merely tolerated.
2. **effect-auth may not depend on legation**, in any package here — not as a dependency, a peer
   dependency, an optional dependency, or a dev dependency. The dependency edge between those two
   libraries runs the other way: the adapter that carries an effect-auth session into a legation
   replica lives in legation, with effect-auth as an _optional_ peer there.
3. **legation requires neither of the other two.** An application may adopt legation without
   adopting JSON:API or effect-auth.

Because those edges only run one way, released changes propagate in that order too: effect-jsonapi
first, then effect-auth, then legation.
