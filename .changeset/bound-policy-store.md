---
"@thomasfosterau/effect-auth": minor
---

Bound stored policy conditions and batch template loading. The `Condition` schema now rejects a condition more than `Condition.maxDepth` (64) levels deep or with more than `Condition.maxNodes` (4096) nodes before decoding it, so an over-deep stored document fails as a `SchemaError` instead of a stack-overflow defect; `Condition.isWithinBounds` checks the same limits, and `memoryPolicyStore` writes reject a condition beyond them. `effectivePolicies` loads templates with one `listTemplates` call instead of a `getTemplate` per link. The `PolicyStore` docs now say that one broken link fails every decision, and that tenant-written policies need validation on write and per-tenant scoping.
