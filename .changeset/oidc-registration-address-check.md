---
"@thomasfosterau/effect-auth": minor
---

Dynamic client registration is rate limited per client address, keyed on the `ClientIP` that `Http.make` and `Http.makeAsync` resolve from their `trustedProxy`, the one address source every address-keyed limit shares (#388, #398). With registration enabled in the `services`' `OidcProviderService` and neither `trustedProxy` (for example `ClientIP.cloudflare`) nor `allowMissingClientIp: true`, `Http.make` throws `ClientAddressConfigError` at startup and `Http.makeAsync` rejects with it, before any request. `allowMissingClientIp` skips only that check: a registration with no address is refused with `429`, and is never counted under a shared bucket. `mcpProviderPreset` always enables dynamic registration, so an MCP server's handler must set one of the two. `OidcDynamicRegistrationConfig` has no address options of its own, and `OidcProviderService.layer` no longer fails with `ClientAddressConfigError`.
