# Organization in core, as a separate bounded context

We ship the Organization domain (`Organization`, `Member`, `Invitation`, plus Teams when added)
inside the `effect-auth` package rather than as a sibling `@effect-auth/organization` package. Org
code lives under `packages/effect-auth/src/organization/` to keep the conceptual boundary visible
inside the package, and the dependency direction is one-way — org modules import auth modules,
auth modules never import org.

Conceptually Organization remains a separate bounded context. Its entities are out of the
credential/verification typology from ADR-0006, it has its own glossary section in `CONTEXT.md`,
and its language ("Member" ≠ "User") doesn't overlap with the authentication glossary.

The trade-off: every consumer pays for the org surface even if they don't use it, and core's API
surface grows accordingly. We accept this because (1) a sibling package adds publishing,
versioning, and changeset overhead for a monorepo that today has exactly one publishable package,
(2) the typology rule and physical subdirectory keep the conceptual boundary intact without
needing a publishing boundary, and (3) splitting later is mechanical if the bundle size or API
surface ever becomes a concrete problem.

Admin functionality, when added, gets the same treatment: in `effect-auth` core, under
`packages/effect-auth/src/admin/`, conceptually separate, dependency one-way against auth and
org.
