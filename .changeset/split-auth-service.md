---
"@thomasfosterau/effect-auth": minor
---

Auth as a separate service is now a supported deployment: a remote session-resolution client
and a documented `Set-Cookie` relay (#187).

`Http.make` mounted in its own internal service — reached over a Cloudflare service binding, a
private container, an in-process handler under test — needs two things a typed client cannot
give. Both are new in `Http.RemoteSession`.

**A transport that is not `globalThis.fetch`.** `layerFetcher(binding)` builds an `HttpClient`
from any fetch-alike, so `Http.client(baseUrl)` works unchanged over a service binding. The
typed contract already classifies status codes into tagged failures, which replaces the
hand-written "POST to an auth route and map the status" service this topology otherwise grows.

**A channel for `Set-Cookie`.** `make({ fetcher })` returns a client with `read` (resolve the
session, returning the `Set-Cookie` lines to replay) and `relay` (forward a session-mutating
request and return the upstream response verbatim — status, body and `Set-Cookie` intact).
`resolveAtEdge` / `resolveAtEdgeFailOpen` compose that with #186's credential skip, fault
posture and `AuthOutcome`, so a cookieless request never reaches the binding and an
unreachable one degrades loudly rather than 500ing every route.

Three rules the library now owns rather than each app rediscovering:

- **Header forwarding is an allow-list.** `content-type` and `content-length` are not on it.
  Forwarding an inbound request's content headers onto a bodyless `GET` makes a router believe
  the request has a body, at which point its content-type allow-list rejects the app's own
  dispatch type with 415 — the session fails to resolve, the request degrades to anonymous, and
  every gated route answers 401. An allow-list makes that unreachable rather than something you
  remember to strip.
- **Session _reads_ need the relay too.** With the signed cookie cache on, a read refreshes it
  via `Set-Cookie`; drop that and the cache stops refreshing after its first window, silently.
- **Never relay a cookie to a machine caller.** `Set-Cookie` is dropped unless the inbound
  request carried a browser session cookie and no machine credential — the mixed cookie+key case
  and the bearer-only native client included. `relayResponse` applies the same rule to a
  hand-rolled relay.

`SessionResolution.resolveWith` / `resolveWithFailOpen` generalise the `resolve` pair over a
payload that carries more than the session, so the remote resolver threads its cookies through
the one outcome derivation instead of calling the transport twice.

New guide: `docs/guides/split-auth-service.md` — when to split and when to just mount
`Http.make` in the app, the transport, the fault posture, the relay, and the CSRF implication
of a server-to-server hop (effect-auth's trusted-origin guard allows a request with no `Origin`,
so a binding need not synthesise one — but the forwarded browser origin must be in the auth
service's `trustedOrigins`).
