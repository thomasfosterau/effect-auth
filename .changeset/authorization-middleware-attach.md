---
"@thomasfosterau/effect-auth": patch
---

`makeAuthorizationMiddleware` results can now be attached with `HttpApiEndpoint.middleware(...)` and `HttpApiGroup.middleware(...)`, which rejected them with TS2345. The factory's return type named the class value rather than its instance; it now uses the instance type, the same shape `AuthMiddleware` has. Runtime behaviour is unchanged. The `.layer` property is now typed as providing that instance type, which is what an attached endpoint requires; two types are newly exported, `AuthorizationMiddlewareConfig` and `AuthorizationMiddlewareInstance` (#313).
