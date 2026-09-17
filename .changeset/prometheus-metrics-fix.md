---
"@thomasfosterau/effect-auth": patch
---

BREAKING: Prometheus metric names renamed to comply with naming conventions.

All exported metric counters have been renamed to use underscores exclusively per Prometheus requirements ([a-zA-Z\_:][a-zA-Z0-9_:]\*):

- `effect-auth.sign_in.total` → `effect_auth_sign_in_total`
- `effect-auth.sign_up.total` → `effect_auth_sign_up_total`
- `effect-auth.sessions_created.total` → `effect_auth_sessions_created_total`
- `effect-auth.sessions_validated.total` → `effect_auth_sessions_validated_total`
- `effect-auth.sessions_invalidated.total` → `effect_auth_sessions_invalidated_total`
- `effect-auth.token_verifications.total` → `effect_auth_token_verifications_total`
- `effect-auth.rate_limit_hits.total` → `effect_auth_rate_limit_hits_total`
- `effect-auth.multi_factor_challenges.total` → `effect_auth_multi_factor_challenges_total`
- `effect-auth.multi_factor_verifications.total` → `effect_auth_multi_factor_verifications_total`
- `effect-auth.oauth_callbacks.total` → `effect_auth_oauth_callbacks_total`
- `effect-auth.oauth_refreshes.total` → `effect_auth_oauth_refreshes_total`
- `effect-auth.webauthn_registrations.total` → `effect_auth_webauthn_registrations_total`
- `effect-auth.webauthn_authentications.total` → `effect_auth_webauthn_authentications_total`
- `effect-auth.oidc_token_requests.total` → `effect_auth_oidc_token_requests_total`

OpenTelemetry span names remain unchanged (they use dotted notation) and are now centralized as constants in `Observability.spanNames`.

Anyone scraping these metrics will need to update their queries and dashboards to reflect the new names.
