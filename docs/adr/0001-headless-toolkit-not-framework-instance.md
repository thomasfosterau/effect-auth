# Headless toolkit, not a framework instance

> **Superseded by [ADR-0017](0017-batteries-included-auth-framework.md).** effect-auth ships an
> optional HTTP edge, a typed client and framework bindings; the headless core described below
> survives as one tier of a batteries-included framework rather than as the whole library. The text
> below is left as written.

When asked to "match better-auth's functionality," we deliberately scoped effect-auth as a
**toolkit of composable Effect primitives** rather than a `betterAuth()`-style instance. There is
no central instance, no plugin runtime, no auto-mounted HTTP routes, no shipped client, no
framework integrations, no schema-migration CLI, and no cookie/CSRF helpers. effect-auth provides
the server-side auth _logic_ — Stores, Services, Layers, and free Effect functions — and the
consumer assembles their own app.

The trade-off is real: better-auth's value is largely the integrated runtime and the typed client.
By going headless we lose drop-in adoption and that client story, but we keep the existing Effect
idiom (Context/Layer/Request-Resolver), avoid owning the HTTP edge, and stay storage-agnostic. The
alternative — an architectural clone — would have reshaped the library and added quarters of work
to deliver value we can get most of by composing existing Effect ecosystem pieces.

"Match functionality" therefore means **capability parity at the server-logic layer**, not surface
parity at the API/HTTP/client layer.
