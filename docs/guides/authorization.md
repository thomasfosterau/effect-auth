# Authorization

The policy kernel in practice: RBAC as policies, system principals, and reads of owned and reference material.

There is one authorization model: the policy kernel. `Auth.Rbac` turns a flat role and permission configuration into declarative policies plus the principal → role entity graph:

```typescript
import { Effect } from "effect";
import * as Auth from "@thomasfosterau/effect-auth";

const AuthorizationLive = Auth.Rbac.layer({
  userRoles: { "user-123": ["editor"] },
  rolePermissions: {
    viewer: [{ resource: "posts", action: "read" }],
    editor: [{ resource: "posts", action: "create" }],
    admin: [{ resource: "*", action: "*" }], // superadmin wildcard
  },
  roleHierarchy: { editor: ["viewer"] }, // editor also gets viewer's grants
});

const program = Effect.gen(function* () {
  const authorizer = yield* Auth.Authorizer;

  // Boolean form.
  const canCreate = yield* authorizer.check({
    action: "create",
    resource: Auth.Entity.ref("posts", "post-1"),
  });

  // Enforced form: fails with `AuthorizationDeniedError`, carrying the full
  // decision trace (which policies determined it, and why).
  yield* authorizer.authorize({
    action: "create",
    resource: Auth.Entity.ref("posts", "post-1"),
  });
  return canCreate;
}).pipe(Auth.CurrentPrincipal.provide(Auth.Entity.ref("User", "user-123")));

console.log(await Effect.runPromise(Effect.provide(program, AuthorizationLive)));
```

Because the output is `DeclarativePolicy` data, a rule authored this way is storable, traceable, validatable against an `AuthorizationModel`, and enforceable at the data boundary with `Auth.protectedField`. Mix it with hand-written policies by composing `Auth.Rbac.policies(...)` into your own `Auth.Authorizer.layer({ policies })`. Migrating from the removed `RoleStore` / `AuthorizationPolicy` API? See [docs/guides/authorization-kernel-migration.md](https://github.com/thomasfosterau/effect-auth/blob/trunk/docs/guides/authorization-kernel-migration.md).

### Empty entity ids and types

An entity's id and type are never empty. `Auth.Entity.EntityRef` refuses `""` in either field when
it decodes, and a reference built by hand with one (`Auth.Entity.ref("User", "")` or
`Auth.Entity.ref("", "u1")`) names no entity: it equals nothing, itself included, it is in no
hierarchy, and no type scope matches it (`Policy.isType("")` included). `Auth.Entity.namesEntity`
is the check. `Policy.decidePure` and `Policy.decide` deny a request whose principal, action or
resource has an empty id or type, with reason `"invalid-request"`, before any policy runs, and
`ReadScope.compile` compiles such a principal or action to `ReadScope.deny`. Never use an empty id
or type as a "no user" stand-in: an empty id would match every row whose owner column is `""`. A
signed-out caller is a principal of its own type, such as `Anonymous::"anonymous"`, which
user-typed policies never match. `Guard.make` reads a viewer whose id is empty as anonymous.

### System principals

A background job, cron handler or pipeline step acts with no person behind it. It is a
principal of its own, `System::"<name>"`, not a user and not an API key. It is denied everything
by default and allowed exactly what an explicit grant names:

```typescript
import { Effect } from "effect";
import * as Auth from "@thomasfosterau/effect-auth";

const Model = Auth.AuthorizationModel.make({
  entities: {
    User: {},
    System: Auth.System.declaration, // lets grants validate
    Invoice: {},
  },
  actions: {
    "invoice:charge": { appliesTo: { principal: ["System"], resource: ["Invoice"] } },
  },
});

const AuthorizationLive = Auth.Authorizer.layer({
  model: Model,
  policies: [
    // The billing job may charge invoices, and nothing else.
    Auth.System.grant("billing-cron", {
      id: "billing-cron:charge-invoices",
      action: "invoice:charge",
      resource: Auth.Policy.isType("Invoice"),
    }),
  ],
});

const chargeInvoices = Effect.gen(function* () {
  const authorizer = yield* Auth.Authorizer;
  yield* authorizer.authorize({
    action: "invoice:charge",
    resource: Auth.Entity.ref("Invoice", "inv-1"),
  });
}).pipe(Auth.System.provide("billing-cron"), Effect.provide(AuthorizationLive));

await Effect.runPromise(chargeInvoices);
```

The rules a system principal follows:

- **Denied by default.** Only a permit whose principal scope names the `System` type can allow it
  anything: `System.grant`, `Policy.eq(System.ref(…))`, `Policy.inScope(System.ref(…))` (a group of
  system principals) or `Policy.isType("System")`. The kernel
  enforces this for every policy set, so a permit with no principal scope (`Policy.permit` without
  `principal`, `Policy.permission`, even `{ action: "*", resource: "*" }`, `Policy.action`,
  `Policy.roleAtLeast`, the `OwnedAccess` read policies), a role permit (`Rbac`, `Policy.role`) and a
  `Policy.custom` permit never match one. There is no allow-all for system principals.
- **Named by a grant.** `System.grant` takes one action and one resource scope, so a job is granted what it
  needs and nothing wider. A wider grant is several grants, each with its own id.
- **Not a user.** `System` is a reserved entity type. `Guard.make` refuses it as a viewer's
  principal type, and a user policy (`Policy.isType("User")`, or `Policy.eq(User::"…")`) never
  matches a system principal, nor does a system grant match a user with the same name.
- **No roles.** Role assignment is for users. `Rbac` refuses `"System"` as its principal type, and
  a role permit never matches a system principal, whatever parents a resolver gives it, so a role
  change cannot widen what a job may do. One exception is under the application's control: if its entity resolver places a `Role` inside a `System` group, a grant to that group (`inScope(System::"…")`) reaches every member of the role, users included, so keep `Role` entities out of `System` groups.
- **Named in the audit.** `Authorizer` and `Auth.protectedField` log every decision about a system
  principal with `System::"<name>"` and the policies that decided it (allows at info, denials at
  warning), and a denial's error message names it.

Forbids are not narrowed: an unscoped forbid binds a system principal like everyone else. A forbid
whose condition reads a user attribute therefore errors for a system principal, and an erroring
forbid denies, so scope such forbids to users (`Policy.isType("User")`). See
[ADR 0019](https://github.com/thomasfosterau/effect-auth/blob/trunk/docs/adr/0019-system-principals.md).

`Guard`'s viewer gates (`requireUser`, `requireRoleAtLeast`, `requireOwnerOrRole`) admit users
only. For an operation a job may also perform, `Auth.Guard.requireSystem({ action, resource })` is
the system gate: it admits the current principal when it is a system principal a policy grants the
action (decided by the `Authorizer` in context, so the decision is logged), and yields its
`EntityRef`. Ask the user gate when a viewer is signed in (`guards.isSignedIn`) and the system gate
otherwise; `requireSystem`'s docs have the full example. After the write, report it with
`Auth.recordWrite({ principal, action, resource })`, naming whichever principal passed:
`AuditPlugin` logs it as `auth.write`, so unattended writes are audited alongside a person's.

### Owned and reference material

`Auth.OwnedAccess.make({ guards, viewPrivate })` decides reads of a member's own material: a
`visibility` of `public | followers | group | private`, narrowed by two publication flags (`draft`
and `unapproved`, a moderated row whose state is anything but approved), with `canView(row)` for one
row, `readScope` for a list's `WHERE`, and the `policies` (plus the `binding` they compile against
with `ReadScope.compile`) both are decided by. `Auth.ReferenceAccess.make({ guards, viewPrivate })`
decides ownerless corpus rows on the same axis: read by a `followersOf` account and its followers,
or by a group's members, with no draft or moderation axis; its `readScope` has the owned shape, so
one renderer filters both kinds.

| Row                                | Who may read it                                                    |
| ---------------------------------- | ------------------------------------------------------------------ |
| `public`, published                | everyone, anonymous included                                       |
| `followers`, published             | the owner (reference: the `followersOf` account) and its followers |
| `group`, published                 | the owner (owned rows) and the members of its group                |
| `private`, a draft, or unapproved  | the owner and the `viewPrivate` axis                               |
| no owner (`ownerId: undefined`)    | nobody's own: public and published, or the `viewPrivate` axis      |
| `group` with no group              | read as `private`                                                  |
| reference row with no `visibility` | everyone: the view has no visibility axis                          |

Followers and group members are external facts, read through the `IsFollower` and `IsMember`
seams. Both fail closed: an unprovided seam answers "no" (`isFollowerNever` / `isMemberNever` make
it explicit), and neither is ever asked about a missing owner, followers-of account or group. A
`false` from `canView` is a 404, never a 403.

`Auth.Cacheability.publiclyServeable(Auth.OwnedAccess.serveableAxes)` decides whether a
representation may sit in a viewer-less cache: `visibility` must be `public`, `draft` and
`unapproved` absent or `false`, `moderationState` absent or `"approved"`, and `deletedAt` absent
(`null` included). The four role questions a content application asks — view private material,
view deleted rows, moderate, write the corpus — are `Ladder` axes handed to `Guard`'s gates and
predicates, and each fails closed on a role outside the ladder; the `OwnedAccess.make` example shows
the pattern.
