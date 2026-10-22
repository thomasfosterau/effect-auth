---
"@thomasfosterau/effect-auth": minor
---

System principals get a Guard gate and an audit event (#362, following ADR-0019).

- **`Guard.requireSystem({ action, resource })`** admits the `CurrentPrincipal` when it is a system principal (`System::"<name>"`) that the `Authorizer` in context grants the action on the resource, and yields its `EntityRef`. It fails with `Unauthorized` when there is no current principal or it is not a system principal, and with `Forbidden` when no policy grants it. The decision is the `Authorizer`'s, so it is logged as `authorization.decision` with the job's name. The viewer gates (`requireUser`, `requireRoleAtLeast`, `requireOwnerOrRole`) are unchanged and stay user-only; the `Guard` module docs show both composed for an operation either may perform.
- **`Hooks.afterWrite`**, a new tap carrying a `WriteEvent` (`{ principal, action, resource }`), which the application fires with the new **`recordWrite(event)`** after a write commits. **`AuditPlugin`** logs it as `auth.write` with the acting principal (`User::"<id>"` or `System::"<name>"`), whether it is a system principal, the action and the resource. A `Hooks` implementation written out in full (rather than through `makePlugin` or `Hooks.Default`) needs the new `afterWrite` member.
