# System principals: a reserved entity type with explicit grants

Background work has no person behind it. A queue consumer, a cron handler and a pipeline step
perform writes that a human performs through a gated operation, and the library offered no
principal to gate them on. Applications answered by keeping an ungated twin of the gated
operation, so the safety of a write depended on which function a caller reached for, and the
attribution went missing (`undefined` where the acting account belongs).

[ADR-0018](0018-one-authorization-kernel.md) says there is one authorization model. A system
principal is a principal of that model, so it is decided by the same policies, with no second
path.

## Decision

A system principal is the entity `System::"<name>"`. The library reserves the entity type
`System` for it. The `System` module provides it:

- `System.ref(name)` builds the reference. An empty name is a construction error.
- `System.provide(name)` and `System.layer(name)` provide it as `Authorizer.CurrentPrincipal`,
  with no session and no user. A job runtime needs nothing else.
- `System.grant(name, { id, action, resource, when? })` writes the grant a system principal is
  allowed by: a permit scoped to `System::"<name>"`, naming one action and one resource scope.
  `action` and `resource` are required, so a grant always states what it allows. A hand-written
  declarative permit whose principal scope names the `System` type (`Policy.isType("System")` for
  every job, say) is also explicit, and rule 1 lets it match; nothing else does.
- `System.declaration` is the model entry a deployment adds so that grants validate.

The rules, stated once:

1. **Denied by default.** A system principal is allowed nothing that no policy names. The kernel
   enforces this, not each policy author: a permit reaches a system principal only when its
   principal scope names the `System` type (`eq` or `in` a `System::"…"` reference, or
   `is("System")`). A permit scoped `any`, to another type, or to a role (`in Role::"…"`) never
   matches one, and neither does a `Policy.custom` permit, whose predicate the kernel cannot see
   into. That covers every unscoped permit the library ships or a helper defaults to (the
   `OwnedAccess` policies, `Policy.permission`, `Policy.action`, `Policy.roleAtLeast`) and every
   such permit written later. Forbids are not narrowed: an unscoped forbid binds a system principal
   like everyone else.
2. **Granted explicitly.** It is allowed exactly what a policy grants, and each grant is data:
   stored, validated against the `AuthorizationModel`, and named in a decision trace by its
   policy id.
3. **Never short-circuited.** There is no allow-all branch and no bypass for system principals.
4. **Type-separated.** `System` is distinct from every application principal type. Guard refuses
   it as a viewer's principal type, and the rung and owner policies that Guard builds are scoped
   to the viewer's type, so they cannot match a system entity, whatever attributes the resolver
   gives it.
5. **Audited by name.** Every decision about a system principal, by `Authorizer` or by a
   `protectedField` guard, is logged with `System::"<name>"` and its determining policy ids: allows
   at info, denies at warning. A denial's error message names it too. Decisions about human
   principals are not logged by this module, so nothing changes for them.
6. **No roles.** Role assignment is for users. `Rbac` refuses `"System"` as its principal type, and
   rule 1 keeps a role permit from matching a system principal whatever parents a resolver gives
   it, so a role change can never widen what a job may do. A job is granted with `System.grant`.
   One exception is under the application's control: if its entity resolver places a `Role` inside a `System` group, a grant to that group (`inScope(System::"…")`) reaches every member of the role, users included, so keep `Role` entities out of `System` groups.

## The alternatives we rejected

**Scope each library-shipped permit to the human viewer type** instead of the kernel rule in
rule 1. It closes the permits the library ships today, but not the next unscoped permit, nor one an
application writes with `Policy.permit`'s default: every one would have to remember to exclude
system principals, and the first that forgot would grant jobs what it grants users. The kernel rule
holds for all of them at once. It changes nothing for any other principal, because it applies only
when the request's principal is a system principal.

**A short-circuit: "system is allowed everything", or allowed an axis set without a policy.**
This is the shape a system principal would take if it were a flag rather than an entity. It is a
blanket bypass, which is worse than the ungated twin it replaces: nothing in the policy set says
what a job may do, and nothing in an audit says what it did. The explicit grant costs one policy
per job, and that cost is the point.

**A Guard option that maps a named system principal to an axis set.** Guard's gates yield the
viewer, typed as the application's user, and a system principal has none. Extending the gates
would change their return type for every consumer. The grant above states the same thing as data
the kernel already decides, so Guard's gates stay user gates. Whether Guard gates should also
admit a system principal is a separate decision, recorded in the pull request that adds this ADR.

**A system viewer shaped like a user** (for example `{ id: "system:translation-pipeline", role:
"contributor" }` supplied through `SessionContext.viewerLayer`). It works, and it is the interim
recipe, but it fabricates a user row: the audit trail names a `User`, and the rung is a
configuration fact about a person. The distinct entity type exists so that a system principal
cannot be mistaken for a user.

**Machine credentials are a different thing.** An API key resolves to a real account and inherits
that account's rung. A system principal has no account and holds only what its grants name.
Reaching for an API key where a job needs a principal is how an unattended job ends up with a
long-lived admin credential in an environment variable, so the two stay separate.

## What this does not decide

Whether Guard's viewer gates should also admit a system principal, and how the existing
`Audit` plugin should record one. The `Audit` plugin observes sign-up, sign-in and sign-out, which
a system principal never performs, so it has no event to record for one. The decision log of
`Authorizer` carries the system identity instead. Both are left for a follow-up issue.

Both were decided in #362. The viewer gates stay user-only. A separate gate,
`Guard.requireSystem`, admits a system principal that a policy grants the action, decides it
through `Authorizer`, and yields its `EntityRef`. An operation either may perform asks the user
gate when a viewer is signed in and the system gate otherwise. The `Hooks` layer gains an
`afterWrite` event that the application fires with `recordWrite` after a write, naming the acting
principal, user or system. The `Audit` plugin logs it as `auth.write`, so the `Authorizer` decision
log is not the only audit trail for unattended writes.

Read scopes for background reads (#203) are also out of scope here. A system principal's read
scope is an explicit grant with the same shape as a write grant, so a read scope can reuse this
decision once #203 settles its own.
