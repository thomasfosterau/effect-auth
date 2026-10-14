---
"@thomasfosterau/effect-auth": minor
---

Add system principals: a reserved `System::"<name>"` entity for background jobs, cron handlers and pipeline steps, denied everything by default and allowed exactly what an explicit grant names (#192).

- `System.provide(name)` and `System.layer(name)` provide `Authorizer.CurrentPrincipal` as the named system principal, with no session or user.
- `System.grant(name, { id, action, resource, when? })` builds the grant: a permit scoped to that principal, naming one action and one resource scope. `System.declaration` is the model entry grants validate against.
- `System.ref`, `System.isSystem` and `System.entityType` construct and recognise the reserved type.
- The policy kernel keeps system principals default-deny under every policy set (#377): a permit reaches a system principal only when its principal scope names the `System` type (`System.grant`, `Policy.eq(System.ref(…))`, `Policy.isType("System")`). Unscoped permits (`Policy.permit` with no principal, `Policy.permission`, including `{ action: "*", resource: "*" }`, `Policy.action`, `Policy.roleAtLeast`, the `OwnedAccess` policies), role permits and `Policy.custom` permits never match one. Forbids bind system principals like any other principal.
- Role assignment is for users: `Rbac.entities`, `Rbac.model` and `Rbac.layer` refuse `"System"` as the principal type.
- `Guard.make` refuses `"System"` as a viewer's principal type, and its rung and owner policies are scoped to the viewer's principal type.
- `Authorizer` and `protectedField` log every decision about a system principal, allows at info and denials at warning, with the principal's name and the determining policy ids. A denial's error message names the principal.
