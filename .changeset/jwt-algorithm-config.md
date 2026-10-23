---
"@thomasfosterau/effect-auth": patch
---

`jwtServiceConfig` (and so `JwtService.layerFromEnv`) now validates `JWT_ALGORITHM`. An unset variable still selects the default algorithm, but a value other than `ES256` or `EdDSA` fails the config with a `ConfigError`. Previously any value was cast through unchecked, and a read failure was swallowed into "unset" (#443).
