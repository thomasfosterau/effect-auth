# Architecture Decision Records

ADRs 0001–0016 are historical decision records that predate the July 2026 API
restructure, so they use pre-restructure names and paths (e.g. `TwoFactor`,
`HttpServer.ts`, flat `src/<Feature>.ts` modules). They are deliberately left
as written. See [docs/ARCHITECTURE.md](../ARCHITECTURE.md) for the module map
as it stands today.

More than naming has drifted. A record here states the decision as it was taken, and some of those
decisions have since been reversed — ADR-0001 and ADR-0003 described a library narrower than the one
that ships. Supersession is marked at the top of the superseded file and in the index below; an ADR
with no such marker still stands. For what the library is today, read
[ADR-0017](0017-batteries-included-auth-framework.md) and
[docs/BOUNDARY.md](../BOUNDARY.md) before anything else in this directory.

| ADR                                                          | Title                                                               | Status                                                                                             |
| ------------------------------------------------------------ | ------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------- |
| [0001](0001-headless-toolkit-not-framework-instance.md)      | Headless toolkit, not a framework instance                          | **Superseded by [0017](0017-batteries-included-auth-framework.md)**                                |
| [0002](0002-unified-data-model.md)                           | Account unified; verification per-feature                           | Accepted                                                                                           |
| [0003](0003-protocol-server-plugins-out-of-scope.md)         | Protocol-server plugins out of scope; token primitives in           | **Superseded by [0017](0017-batteries-included-auth-framework.md)**                                |
| [0004](0004-hashed-tokens-at-rest.md)                        | Hash all single-use tokens at rest                                  | Accepted                                                                                           |
| [0005](0005-second-factor-entities-separate-from-account.md) | Second-factor entities are separate from Account                    | Accepted                                                                                           |
| [0006](0006-credential-verification-typology.md)             | Credential/Verification typology                                    | Accepted                                                                                           |
| [0007](0007-account-linking-policy.md)                       | Account linking policy                                              | Accepted                                                                                           |
| [0008](0008-organization-in-core.md)                         | Organization in core, as a separate bounded context                 | Accepted                                                                                           |
| [0009](0009-organization-data-model-and-permissions.md)      | Organization data model and Statement-based permissions             | Accepted; roles, permissions and active-org storage revised in code (see the file's header)        |
| [0010](0010-organization-managed-identity.md)                | Organization-managed identity (User and Account ownership)          | Accepted                                                                                           |
| [0011](0011-jwt-design.md)                                   | JWT design                                                          | Accepted                                                                                           |
| [0012](0012-api-key-design.md)                               | ApiKey design                                                       | Accepted; permission shape kept, no longer shared with organization checks (see the file's header) |
| [0013](0013-provider-expansion-pattern.md)                   | Provider expansion: per-provider TypeScript files                   | Accepted                                                                                           |
| [0014](0014-admin-domain.md)                                 | Admin domain                                                        | Accepted; admin check and ban storage revised in code (see the file's header; also 0015)           |
| [0015](0015-feature-local-entities-for-opt-in-state.md)      | Feature modules are opt-in; feature-local entities for opt-in state | Accepted for opt-in modules; feature-local entities not adopted (see the file's header)            |
| [0016](0016-hierarchical-teams.md)                           | Hierarchical Teams within Organization                              | Accepted                                                                                           |
| [0017](0017-batteries-included-auth-framework.md)            | Batteries-included auth framework, not a headless toolkit           | Accepted; supersedes 0001 and 0003                                                                 |
| [0018](0018-one-authorization-kernel.md)                     | One authorization kernel; RBAC is authoring sugar over it           | Accepted                                                                                           |
