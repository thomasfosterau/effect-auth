---
"@thomasfosterau/effect-auth": minor
---

Dynamic client registration is rate limited per client address, so `OidcProviderService.layer` (and `OidcProvider.make`) now needs an address source for it. When `dynamicRegistration` is set and neither `dynamicRegistration.trustedProxy` nor the opt-out `dynamicRegistration.allowMissingClientIp: true` is declared, the layer fails at build with `ClientAddressConfigError`, before any request. `trustedProxy` takes the same value as the app's `Http.make` `trustedProxy` (for example `ClientIP.cloudflare`); the OIDC layer uses it only for this check and resolves no addresses itself. The opt-out skips only the build check: a registration with no address is still refused with `429` when a `RateLimiter` is in `services`, and is never counted under a shared bucket. `mcpProviderPreset` always enables dynamic registration, so an MCP provider now declares one of the two as well (#388).
