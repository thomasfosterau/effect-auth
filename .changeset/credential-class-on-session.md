---
"@thomasfosterau/effect-auth": minor
---

Record the credential class on the session at issuance. **Breaking:** the class a request is judged by now comes from the session, never from the carrier of its token.

- A session issued by the device grant carries `attributes.credentialClass: "machine"`; every other session reads as `"interactive"`. `sessionCredentialClass(session)` reads it, and `SessionService.setSessionAttributes` never changes it (nor `attributes.deviceGrant`), so a machine-issued session can never become interactive.
- `AuthMiddleware` (both schemes) and `OptionalAuthMiddleware` provide `CurrentCredential` from the session: a browser session's token sent as `Authorization: Bearer` stays interactive. `Http.credentialClassFromRequest` is removed. `SessionResolution.credentialClassOf(presence, session?)` takes the resolved session (an API key is still `"machine"`), `RemoteSession`'s `EdgeSession.credentialClass` follows it, and `SessionContext.authenticatedLayer` defaults to the session's class.
- `PATCH /api-keys/:id` requires an interactive session, as `POST /api-keys` does, so a machine session cannot widen a key's permissions, expiry or uses (`403`).
- `Authorizer` and `Protected`'s `protectedField` build their policy request with one helper, so a protected field's decision sees `CurrentCredential` as `context.credentialClass`, as `Authorizer.check` does.
