# Feature modules are opt-in; feature-local entities for opt-in state

> **Partly revised in code.** Features are still opt-in by import, but their state was not given
> feature-local entities: anonymous, ban and last-login-method state live in the `attributes` of
> the User or Session (`Anonymous.ts`, `Admin.ts`, `plugins/LastLoginMethod.ts`). See
> [docs/CONTEXT.md](../CONTEXT.md). The text below is left as written.

The library's features are individually opt-in by import. Some features need to attach state to a
User (or another canonical entity) — "is this user anonymous," "is this user banned," "what
method did they last sign in with." The default placement for such state is a **feature-local
entity** with its own store, not a column on the canonical entity.

Three patterns were considered. _Optional fields on the canonical entity_
(`User.isAnonymous?`, `User.bannedAt?`) is simplest and matches better-auth, but the columns are
always present in the type and schema even for deployments that never use the feature — "optional"
only at the data level, not structurally. _Type mixins per feature_ is composable at the type
level but TypeScript-heavy and doesn't address the schema. _Feature-local entities_
(`AnonymousMarker { userId, createdAt }`, `Ban { userId, reason, expiresAt }`,
`LastLoginRecord { userId, method, at }`) each have their own store: don't provide the store, don't
get the feature.

We pick feature-local entities. It matches ADR-0002's per-feature philosophy (we already chose
per-feature entities over a generic verification table); it makes opt-in _structural_ rather than
presentational; it keeps the canonical `User` type minimal so future features don't bloat it; and
it tree-shakes cleanly at the type level. Specifically, `AnonymousMarker`, `LastLoginRecord`, and
`Ban` (revising ADR-0014) all become feature-local entities rather than User columns.

Three exception classes exist where state stays on a canonical entity, justified case-by-case:

- _Foundational_ fields: `User.email`, `User.emailVerified`, `User.createdAt` — every User has
  them; not a feature.
- _Cross-domain pointers_: `User.ownedByOrganizationId`, `Account.ownedByOrganizationId` (ADR-0010)
  — explicit relationships to another bounded context with no opt-in alternative.
- _Security-critical signals_: `Session.impersonatedBy` (ADR-0014) — must be visible at every
  auth check; a separate entity would force a join on every authorisation decision and is the
  wrong shape for a signal this load-bearing.

The placement rule for any future "flag on a User-or-similar" question: foundational →
canonical-entity field; security-critical → canonical-entity field with explicit justification;
opt-in feature → feature-local entity.

The trade-off: more entities and stores for consumers to implement when they opt into features.
We accept this because structural opt-in is the point — invisible features should be invisible at
every level, including the schema.
