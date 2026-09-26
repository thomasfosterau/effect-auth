---
"@thomasfosterau/effect-auth": minor
---

Add zero-IO guards over an already-resolved viewer (#189). `Guard.make({ ladder, viewer })` builds,
for one ladder and one application-declared viewer service (`Option<AppUser>`, where
`AppUser extends { id: string; role: string }`):

- gates that yield the viewer or fail — `requireUser` (`Unauthorized`), `requireRoleAtLeast(axis)`
  and `requireOwnerOrRole(ownerId, axis)` (`Unauthorized | Forbidden`);
- never-failing predicates that treat anonymous as `false` — `isSignedIn`, `hasRoleAtLeast`,
  `isOwnerOrRole` — for read paths, where a `false` becomes a 404, never a 403;
- capability hooks — `roleCapabilities(axis)` and `ownedCapabilities(axis, ownerOf)` — that restate a
  write gate as `meta.canEdit` / `canDelete`;
- `policies.roleAtLeast` / `policies.ownerOrRole`: the declarative policies the gates decide.

Every decision is `Policy.decidePure` over a slice built from facts the caller already holds, so the
gates need no `EntityResolver` or `Authorizer`, and a gate cannot disagree with a stored policy built
from the same axis.

`Unauthorized` and `Forbidden` are now defined in the core (and exported from the root); the HTTP
tier's `Http` error schemas re-export the same classes, so a guard's failure encodes at the edge
without translation.

`SessionContext.viewerLayer(tag, user)` and `SessionContext.viewerFromSession(tag, project)` provide
an application's viewer service; `SessionContext.withRole(attribute)` projects the library's
`SessionWithUser` into a viewer whose rung is read from `user.attributes`.
