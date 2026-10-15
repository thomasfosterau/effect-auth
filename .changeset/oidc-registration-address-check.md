---
"@thomasfosterau/effect-auth": minor
---

Dynamic client registration is rate limited per client address, so `OidcProviderService.layer` (and `OidcProvider.make`) needs an address source when `dynamicRegistration` is set. With neither `dynamicRegistration.trustedProxy` nor the opt-out `dynamicRegistration.allowMissingClientIp: true`, the layer fails at build with `ClientAddressConfigError`, before any request. `trustedProxy` takes the same value as the app's `Http.make` `trustedProxy` (for example `ClientIP.cloudflare`); the OIDC layer uses it only for this check and resolves no addresses itself. The opt-out skips only the build check: a registration with no address is refused with `429` when a `RateLimiter` is in `services`, and is never counted under a shared bucket. `mcpProviderPreset` always enables dynamic registration, so an MCP provider must also declare one of the two (#388).

`ClientAddressConfigError` is exported from the package root as well as from `./http` (`Http.ClientAddressConfigError`); both names are the same class.
