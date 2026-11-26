---
"@thomasfosterau/effect-auth": minor
---

SSO sign-ins are now bound to the browser that started them, and the SAML ACS works cross-origin.

- `POST /sso-authorizations` sets a pre-login cookie, `<name>_sso_state` (`HttpOnly`, `SameSite=None; Secure`, ten minutes), holding the round-trip state. `POST /sso/callback` answers `400` unless the request carries the cookie for its `state`, and the SAML ACS refuses an SP-initiated response unless the cookie holds that request's `RelayState`. An attacker can no longer finish the IdP leg as themselves and have a victim's browser complete it (login CSRF). Both clear the cookie when they sign the user in.
- `POST /oauth2/token`, `POST /register` and `POST /sso/saml/acs/:providerId` are exempt from the Origin check: cross-site callers post to them by design, and each carries its own proof. Before, the IdP's form POST to the ACS was refused with `403` unless the IdP's origin was in `trustedOrigins`, which trusted it on every endpoint. Remove an IdP origin you added there for SAML.
- `SsoService.handleSamlCallback` takes an optional fourth argument, `{ browserState }` (`SamlCallbackOptions`): when given, a response that answers a request is accepted only if `browserState` equals that request's `RelayState`. IdP-initiated responses (`allowIdpInitiated`) are not checked, since no browser holds a state for them, and the `allowIdpInitiated` docs no longer claim `InResponseTo` prevents login CSRF.

**Breaking:**

- The SAML ACS answers `303` instead of a JSON body: to `sso.redirectTo` (default `/`) with the session cookie, or to `sso.errorRedirectTo` (default `redirectTo`) with `error=access_denied`, `temporarily_unavailable` or `server_error`. A sign-in that owes a second factor goes, with no session, to `sso.secondFactorRedirectTo` (default `redirectTo`) with the challenge in the fragment, `#second_factor=<token>&expires_at=<ms>`, for `POST /second-factor-challenges/verifications`. Configure them with the new `sso` option of `Http.make` and `Http.makeAsync` (`SsoRedirectConfig`), the fourth argument of `groupLayers` or the third of `authGroupLayer`.
- `Http.ssoAuthorizationsGroupLayer` is now a function, `ssoAuthorizationsGroupLayer(cookie?, multiSession?)`, so it names the same cookie as `authGroupLayer`. Pass it the same cookie config.
- A host that serves `POST /sso/callback` from its own page must let the browser send the pre-login cookie (same site, or `credentials: "include"`, as the browser client already does).
