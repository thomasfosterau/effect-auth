---
"@thomasfosterau/effect-auth": minor
---

Add system principals: a reserved `System::"<name>"` entity for background jobs, cron handlers and pipeline steps, denied everything by default and allowed exactly what an explicit grant names (#192).

- `System.provide(name)` and `System.layer(name)` provide `Authorizer.CurrentPrincipal` as the named system principal, with no session or user.
- `System.grant(name, { id, action, resource, when? })` builds the grant: a permit scoped to that principal, naming one action and one resource scope. `System.declaration` is the model entry grants validate against.
- `System.ref`, `System.isSystem` and `System.entityType` construct and recognise the reserved type.
- `Guard.make` refuses `"System"` as a viewer's principal type, and its rung and owner policies are scoped to the viewer's principal type, so they cannot match a system principal.
- `Authorizer` logs every decision about a system principal, allows at info and denials at warning, with the principal's name and the determining policy ids. A denial's error message names the principal.
