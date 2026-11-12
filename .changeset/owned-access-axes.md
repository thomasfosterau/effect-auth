---
"@thomasfosterau/effect-auth": minor
---

`OwnedAccess` gains the axes a content kernel needs to delegate its read rules (#637), and a new `ReferenceAccess` module decides ownerless reference rows.

- **Moderation:** `OwnedRow.unapproved?: boolean | undefined`, read exactly as `draft: true`. The `owned:public`, `owned:follower` and new `owned:group` permits require it to be `false`; the owner and view-private permits ignore it.
- **No owner:** `OwnedRow.ownerId` is now `string | undefined` (breaking). `undefined` means the row has no owner: no viewer matches the owner arm, and the decision slice carries no `owner` attribute, never an empty or sentinel id. `IsFollower` is never asked about it.
- **Groups:** `Visibility` gains `"group"` (breaking for exhaustive matches), `OwnedRow.groupId?: string | undefined` names the group, and the new `IsMember` service (`isMember`, `groupsOf`, with `isMemberNever`) answers membership. It fails closed when it is not provided, like `IsFollower`. The new `owned:group` permit admits a published `group` row to members of its group. A `group` row with no group reads as `private`.
- **Read scope:** the `member` arm of `OwnedReadScope` gains `groups: FollowingSet` (breaking for code that builds the scope), which is `nobody` without `IsMember`.
- **Reference rows:** `ReferenceAccess.make({ guards, viewPrivate })` returns `canView(row: ReferenceRow)`, the same `OwnedReadScope`-shaped `readScope`, `policies` and `binding`. A row with no `visibility` (the view has no axis) is visible to everyone. A `followers` row is read by its `followersOf` account and that account's followers, and a `group` row by its group's members. The view-private rung reads everything.
- **Seams:** `OwnedAccess.relationFacts(accountId, { followersOf, groupId })` asks both seams, failing closed. It never asks about an absent subject.
- **Compiling the policies:** `OwnedAccess` and `ReferenceAccess` expose `binding`, the `ReadScope.Binding` their `policies` compile against. The owned binding now binds `unapproved` and `group`, and `context.member` is the set `groups`.
- **Serveability:** `OwnedAccess.serveableAxes` adds `unapproved` (optional, must be `false`), `moderationState` (optional, must be `"approved"`) and `deletedAt` (must be absent). A representation that carries none of them is decided as before.
- **Docs:** the `OwnedAccess` module docs describe the four role axes (`viewPrivate`, `viewDeleted`, `moderate`, `writeCorpus`) and their fail-closed rule for a role outside the ladder.

Migration: pass `ownerId: undefined` instead of coercing a missing owner to a string, and add `groups` wherever you build a `member` read scope. Give the owned rows your `EntityResolver` hands an `Authorizer` an `unapproved` boolean (`false` for an unmoderated row): like `draft`, a missing `unapproved` now reads as unpublished, so `owned:public` no longer admits the row. `ReadScope.compile` over `OwnedAccess.policies` needs a binding that binds `unapproved` and `group`; use `owned.binding`. An older binding compiles to `Inexact`, which `Cacheability.publicReach` reports as `Undecided`.
