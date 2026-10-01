---
"@thomasfosterau/effect-auth": patch
---

Metric counter names follow the Prometheus naming rule (`[a-zA-Z_:][a-zA-Z0-9_:]*`), using underscores only: `effect_auth_sign_in_total`, `effect_auth_sign_up_total`, `effect_auth_sessions_created_total`, `effect_auth_sessions_validated_total`, `effect_auth_sessions_invalidated_total`, `effect_auth_token_verifications_total`, `effect_auth_rate_limit_hits_total`, `effect_auth_multi_factor_challenges_total`, `effect_auth_multi_factor_verifications_total`, `effect_auth_oauth_callbacks_total`, `effect_auth_oauth_refreshes_total`, `effect_auth_webauthn_registrations_total`, `effect_auth_webauthn_authentications_total` and `effect_auth_oidc_token_requests_total`.

OpenTelemetry span names use dotted notation and are exported as constants in `Observability.spanNames`.
