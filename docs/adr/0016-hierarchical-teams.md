# Hierarchical Teams within Organization

Teams are an opt-in sub-grouping of Members within an Organization, supporting a single-parent
tree hierarchy. `Team { id, organizationId, name, parentTeamId? }`. `TeamMembership { teamId,
memberId }` joins Teams to Members (not Users directly) — so being on a Team requires being a
Member of the Team's Organization, and the schema enforces the invariant without library checks
on every insert.

**Tree, not DAG.** A Team has at most one parent. Multi-parent hierarchies turn every traversal
into a graph walk, cycle prevention into a topological sort, and "where does this team belong?"
into a non-deterministic question. DAG semantics can be added later if real demand appears;
reversing from DAG back to tree is much harder.

**Membership is explicit per node — no cascade down.** Being on team Engineering does *not*
implicitly make you a Member of its sub-team Backend. The hierarchy's value is permission cascade,
not membership cascade. Auto-cascading membership makes roster queries ambiguous, inflates lists
silently, and turns deletes into propagation puzzles.

**Permission cascade is narrow: only `team`-resource permissions cascade down ancestors.** A
Member whose role grants `team: ["manage", "view-roster"]` on team Engineering automatically has
those `team` actions on every descendant. Non-`team` resources (`document`, `issue`, etc.) are
*not* automatically team-scoped just because hierarchy exists — they remain Org-level unless the
consumer composes team-scoped checks on top. This keeps hierarchy semantics narrow and
predictable: ancestors manage their subtree, nothing more.

**`TeamAccessControl` is a sibling service to `OrganizationAccessControl`.** Its
`hasPermission(teamId, userId, statement)` walks ancestors looking for a role that grants the
requested `team` actions on the target team or any of its ancestors. Adding a `scope: { teamId? }`
parameter to the org service was considered and rejected — a separate service makes "team-scoped
check with ancestor cascade" structurally obvious at the call site. Both services share the
`RoleStore` and `PermissionStatement` machinery.

**Depth is configurable, defaults to 8.** `maxTeamDepth: number` caps how deep the tree can grow.
Creating or re-parenting a Team whose chain would exceed this returns a structured error. 8 is
deeper than any realistic org-chart need, shallow enough to bound worst-case ancestor walks. The
library also enforces cycle prevention on `setParentTeam` — re-parenting under self or any
descendant is rejected.

**No default Team on Org creation.** Auto-creating a "Members" team would force every consumer to
opt out, and the convenience is thin (it's one call). Deployers who want one create it
explicitly.

The `TeamStore` interface requires `findAncestors`, `findDescendants`, and `findChildren`
alongside CRUD; the library doesn't dictate adjacency-list versus closure-table — the consumer
picks based on their database. Library-side enforcement is limited to cycle prevention and depth
checking; everything else flows through the store interface.

The trade-off in this ADR: hierarchical Teams is materially more complex than flat. We accept the
cost (extra entity, extra service, ancestor walks at check time, depth/cycle invariants) because
the alternative — a flat Team model — is too thin to be worth its own ADR, and consumers who need
hierarchy would otherwise rebuild it themselves with worse invariants.
