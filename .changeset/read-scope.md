---
"@thomasfosterau/effect-auth": minor
---

New `ReadScope` module (ADR-0020, #203): compile a declarative policy set into the rows a principal may read, for a LIST to render as its `WHERE`. `ReadScope.compile(policies, binding, request)` partially evaluates the policies over an unbound row and returns `Exact` with one of three scopes: `AllowAll`, `Deny`, or a `Filter` over a bound-scalar `Predicate` (text, integer, double, boolean, instant). Relationships compile to named sets (`InSet`), never inlined members. A policy the predicate can't express is flagged `Inexact` with its reasons, never approximated. The predicate is two-valued: absence is its own atom, so the kernel's absent-attribute rule survives the move to SQL. `ReadScope.matches` is the single-row form of the same residual, and `ReadScope.withoutSets` narrows a scope whose sets can't be resolved. `Condition.evaluateOperand` is now exported.
