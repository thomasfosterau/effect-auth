---
"@thomasfosterau/effect-auth": minor
---

`makeAuthorizationMiddleware` now takes the guard's name as its first argument: `makeAuthorizationMiddleware("RequireDocRead", input)`. The name is the guard's TypeScript type, so attaching one guard to an endpoint and providing only another guard's `.layer` is now a compile error. Before, both guards had the same type, the wrong layer type-checked, and the request failed at runtime with a missing service (#320). Calls without a name no longer compile; the name also labels the runtime tag, which stays unique per call.

The name must be a single string literal. A `string`, a template pattern such as `` `${string}Guard` `` or a union is a compile error, because it would widen the guard's type to the others'.

Migration:

```ts
// before
const RequireDocRead = makeAuthorizationMiddleware(input);

// after
const RequireDocRead = makeAuthorizationMiddleware("RequireDocRead", input);
```

The middleware's types are now checked rather than widened to `any`, so an attached guard's requirements (`Authorizer`, `CurrentPrincipal`, and the input's own services other than the router's per-request ones) appear in the endpoint's layer requirements. New export: `AuthorizationRequires`. `AuthorizationMiddlewareClass` and `AuthorizationMiddlewareInstance` take the name as an optional second type parameter, so existing type references still compile.
