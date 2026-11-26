---
"@thomasfosterau/effect-auth": minor
---

The device authorization grant's device endpoints speak RFC 8628 on the wire. **Breaking** for every device client:

- `POST /device/code` takes `client_id` and a space-delimited `scope` (form-encoded, as RFC 8628 §3.1 specifies, or JSON) and answers `device_code`, `user_code`, `verification_uri`, `verification_uri_complete`, `expires_in` and `interval`. `DeviceBeginResult` gains `verificationUriComplete` (`verificationUri` with `?user_code=`).
- `POST /device/token` takes `grant_type=urn:ietf:params:oauth:grant-type:device_code`, `device_code` and `client_id`. An approved poll answers an RFC 6749 token response, `{ access_token, token_type: "Bearer", expires_in, scope }`, whose `access_token` is the device's session token, sent as `Authorization: Bearer`; it no longer sets a session cookie or answers the user.
- Every refusal from either endpoint is a `400` RFC 6749 error object, `{ error, error_description }`, instead of `{ message }`: `invalid_request`, `invalid_client`, `invalid_scope`, `unsupported_grant_type`, `invalid_grant`, `authorization_pending`, `slow_down`, `access_denied` and `expired_token`. A session hook refusing the grant (a ban or lockout) is `access_denied`, and a hook's rate limit `slow_down`.
- `DeviceAuthorizationService.poll(deviceCode, clientId?)` refuses a device code issued to another client with `invalid_grant`, before it writes anything.
- The browser client's `device.code` and `device.token` take and answer the RFC shapes (`DeviceTokenView`), and an `AuthClientError` from an RFC-tier error object carries its `error` as the message.
