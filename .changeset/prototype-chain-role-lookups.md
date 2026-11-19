---
"@thomasfosterau/effect-auth": patch
---

Read role names, attribute paths and model ids only as a record's own keys. A member role named `constructor`, `__proto__` or another `Object.prototype` member is now an unknown role, so its permission checks deny instead of failing with a defect, and `setDefaultRole` and `addMember` refuse it. In the authorization kernel, `Condition.has` and `Condition.attr` treat such a path segment as absent, `Entity.getAttribute` returns `null` for it, `Rbac.entities` gives such a role no inherited parents, and `AuthorizationModel.validatePolicies` reports such an action, entity type or attribute as undeclared.
