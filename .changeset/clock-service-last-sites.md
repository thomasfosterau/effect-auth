---
"@thomasfosterau/effect-auth": minor
"@thomasfosterau/effect-auth-sql": patch
"@thomasfosterau/effect-auth-saml": minor
---

Time is read from the `Clock`, and instants from outside are decoded rather than trusted (#443). **Breaking** for these call sites:

- `makeIdentifier` and `PolicyStore.makeLink`: `now` is now **required**. Pass the caller's time, e.g. `now: yield* DateTime.nowAsDate`.
- `isBanned(user)` now returns `Effect<boolean>`, reading the `Clock`, so `TestClock` decides when a ban lapses: `const banned = yield* isBanned(user)`.
- `Testing.sessionFor(user, now)` now returns `Effect<SessionWithUser, SchemaError>`, failing on an Invalid Date instead of building one.
- `Http.fromSessionWithUserView(view)` (`./http`) now returns `Effect<SessionWithUser, SchemaError>`: the remote server's epoch millis are decoded with `Schema.DateFromMillis`. `RemoteSession`'s `read` reports an undecodable instant as a `RemoteSessionError` ("Session read body did not decode").

effect-auth-sql decodes stored epoch-millis columns with `Schema.DateFromMillis`; a value outside the `Date` range fails as an `AuthError` instead of producing an Invalid Date.

effect-auth-saml reads `NotOnOrAfter` instants as UTC via `DateTime`, and **rejects** an instant with no time zone (SAML `xs:dateTime`s must carry one) or one that does not parse, where it used to read a zone-less instant as the server's local time and ignore an unparseable one.
