---
"@thomasfosterau/effect-auth": minor
---

**Breaking:** store contracts answer a miss with `Option` instead of `null`. Every store lookup that can legitimately find nothing (`SessionStore.get` and `touch`, `UserStore.get`, `IdentifierStore.getByValue`, the token stores' `get`, `consume` and `getLatestByUserId`, `ApiKeyStore.recordUse`, the organization, SSO, SCIM, OAuth, WebAuthn, OIDC-provider and device-authorization lookups, and the rest) now returns `Effect<Option<X>>`, `Option.none()` on a miss. A hand-written store wraps its driver's answer with `Option.fromNullishOr` (or `Option.fromUndefinedOr`, `Arr.head`), and `succeed(null)` becomes `Effect.succeedNone`. The built-in in-memory, `KeyValueStore` and `/sql` stores and `Testing`'s store conformance suites follow the new contract; service results are unchanged in this release.
