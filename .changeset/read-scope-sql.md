---
"@thomasfosterau/effect-auth-sql": minor
---

New `readScopeWhere(scope, { columns, sets? })` (#190): renders a core `ReadScope` as a SQL `WHERE` fragment over any relation's columns, so a LIST filters in the database. It is two-valued on NULL columns, keeps named sets as subqueries, narrows when a set's fragment is missing, and lists nothing when a column is missing.
