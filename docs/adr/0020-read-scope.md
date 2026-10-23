# The read scope: a bound-scalar predicate this library owns

The kernel ([ADR-0018](0018-one-authorization-kernel.md)) decides one request at a time: may this
principal take this action on this resource. A read of a list asks a different question: which
rows may this principal see. The answer has to reach the database as a filter. Filtering a page
after it is fetched returns short pages, gives wrong totals, and reads rows the viewer was never
entitled to (#190).

Earlier drafts of #203 said the filter _is_ effect-jsonapi's `Filter.Ast`, and made effect-jsonapi's
filter profile a dependency of the kernel. That conflated two questions:

1. What filter syntax does this library's HTTP API accept? effect-jsonapi's
   (`filter[role][eq]=admin`), because that API is JSON:API. This question belongs to the HTTP tier.
2. What does a policy compile to when it is evaluated over a set of rows? This is an authorization
   question, and nothing about the answer is a wire format.

This ADR answers the second.

## Decision

A policy set compiles to a **read scope**: `ReadScope.AllowAll | ReadScope.Deny |
ReadScope.Filter`. The `Filter` case carries a `ReadScope.Predicate`. The `ReadScope` module
(`@thomasfosterau/effect-auth`) owns the predicate type, and projections are written from it where
they are needed: SQL in effect-auth-sql, and later effect-jsonapi's `filter[...]` AST and Drizzle
(the owner's decision on #203, 2026-10-09).

- **Three-way return.** Allowing every row is a branch, `AllowAll`, not a disjunction over every
  axis. A privileged role short-circuits to it, and a renderer emits no filter. `Deny` lets a
  renderer skip the query. `legation#205` arrived at the same shape for its auth filters
  independently.
- **Bound scalars only.** A predicate compares a resource attribute with a scalar of one of five
  kinds: text, integer, double, boolean or instant. Those are the values a database binds as
  parameters. Entity hierarchies, arrays and records have no place in it.
- **Absence is an atom.** `Eq` and `Compare` hold only for a present attribute, and `IsNull` tests
  for absence. Each atom is two-valued, so a projection to SQL never meets SQL's third truth value.
  The kernel's rule that reading an absent attribute is an evaluation error (a permit then cannot
  grant and a forbid denies) is compiled into these atoms. It is not left to the database's NULL
  logic: on a row whose `visibility` is NULL, `NOT (visibility = 'private')` would otherwise exclude
  the row under three-valued logic and admit it under a two-valued reading.
- **Relationships are named sets.** "The owner is someone the viewer follows" compiles to
  `InSet(owner, "following")`: the predicate names the set and never carries its members. The
  application resolves the set as a subquery or semi-join at render time, and the row-at-a-time
  path as a membership test. The authored form does not change between requests, so a
  subscription's identity doesn't churn and nothing is resolved per row. This is why
  `effect-jsonapi#119` (a relational filter node) was closed: no upstream grammar change is needed.
- **Exactness is in the type.** Compilation returns `Exact(scope)` or `Inexact(reasons)`, and only
  an exact scope is a filter. A policy whose condition can't be expressed in the predicate (a
  `Policy.custom` predicate, entity-hierarchy `in`, array `contains`, an attribute whose kind the
  binding doesn't declare) makes the result `Inexact`, with the reason. It is never approximated,
  because an approximate filter is either a privacy leak or a wrong total.
- **Fail closed on an unresolvable set.** A runtime that can't resolve a named set substitutes the
  value that narrows the scope at each occurrence: false where the set is used positively, true
  under a negation (`ReadScope.withoutSets`). An unprovided seam therefore never widens the scope
  and never drops a conjunct. This matches `OwnedAccess.isFollowerNever`.
- **One residual, two shapes.** The per-row predicate is the same `Predicate`, evaluated over one
  row with the named sets as membership tests (`ReadScope.matches`). A list filter and a row check
  compiled from one policy set cannot drift. The kernel's `Policy.decidePure` stays the source of
  truth, and a property test requires all three to agree over a fixture corpus.

## Why not reuse a neighbour's type

- **effect-jsonapi's `Filter.Ast`** is a wire grammar. It is typed per resource over _decoded_
  attribute values, it is URL-encodable, and it is attribute-local by design: its
  `docs/filter-grammar.md` rules out relationship traversal. Reusing it would bring a
  query-parameter format into the kernel. It would also tie this repo's core to an upstream release
  cycle for a concern that isn't a wire format, and make the core depend on the filter profile's
  NULL semantics (`effect-jsonapi#116`) and on reaching the grammar without the HTTP surface
  (`effect-jsonapi#117`). With this decision, neither is a dependency.
- **legation's `Predicate`** is its sync engine's subset language: the same comparison nodes plus
  `True` and a relational `Exists`, with literal kinds for collation and parameter binding. effect-auth
  may not depend on legation ([BOUNDARY.md](../BOUNDARY.md)). The projection to it is legation's to
  write (`legation#219`), as adapter work over this type.

## Consequences

- `ReadScope` lives in core and imports only `effect` and the kernel modules, so the HTTP tier stays
  optional ([BOUNDARY.md](../BOUNDARY.md)).
- The projections are adapter work. effect-auth-sql renders a scope over a column binding. A binding
  that names a column the source lacks renders deny-all.
- The flat `RoleStore` / `checkPermission` path cannot be partially evaluated: it has no unbound
  resource slot and no condition AST. Rules written through it don't take part in a read scope until
  #204 moves them onto the kernel.
- Policy-derived cacheability (#191) is the degenerate case of the same analysis: "does this
  decision depend on the principal".
