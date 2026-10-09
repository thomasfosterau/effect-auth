---
"@thomasfosterau/effect-auth": minor
---

`makeAuthorizationMiddleware` takes the guard's name as its first argument: `makeAuthorizationMiddleware("RequireDocRead", input)`. The name is the guard's TypeScript type, so attaching one guard to an endpoint and providing only another guard's `.layer` is a compile error rather than a runtime missing-service failure (#320). Two guards built with the same name literal share a type, so a mix-up between them is not caught at compile time.

The name must be one non-empty string literal. A `string`, a template pattern such as `` `${string}Guard` ``, a union or `""` is a compile error: the first three would widen the guard's type to the others', and the last names no guard. The name also labels the runtime tag, `@effect-auth/AuthorizationMiddleware/<name>#<n>`, which stays unique per call.

The middleware's types are checked rather than widened to `any`, so an attached guard's requirements (`Authorizer`, `CurrentPrincipal`, and the input's own services other than the router's per-request ones) appear in the endpoint's layer requirements. New export: `AuthorizationRequires`. `AuthorizationMiddlewareClass` and `AuthorizationMiddlewareInstance` take the name as an optional second type parameter, defaulting to `string`.
