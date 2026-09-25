---
"@thomasfosterau/effect-auth": minor
---

Add an ordered role ladder (#188): `Ladder.make([...rungs])` gives a totally ordered set of rungs,
`rank` (`-1` off the ladder), the one "at least this rung" comparison (`hasAtLeast`, failing closed
on anonymous and on an off-ladder role), and named capability axes (`ladder.axes({ corpusWrite:
"contributor", … })`) so moving a capability between rungs is a one-line change. The module imports
nothing and is also published on its own subpath, `@thomasfosterau/effect-auth/ladder`, so a browser
bundle can read the ladder for UX gates.

`Policy.roleAtLeast(ladder, axis, options)` (and `Policy.roleAtLeastCondition`) compile an axis into
an ordinary declarative policy — `principal.role` is one of the rungs at or above the axis — so a
ladder comparison is storable and model-checkable like any other policy.
`AuthorizationModel.validatePolicies` now also checks, where a policy pins its principal or resource
to a declared type with a struct of attributes, that every attribute its condition reads on that
slot is declared.
