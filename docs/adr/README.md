# Architecture Decision Records

ADRs 0001-0016 are historical decision records that predate the July 2026 API
restructure, so they use pre-restructure names and paths (e.g. `TwoFactor`,
`HttpServer.ts`, flat `src/<Feature>.ts` modules). They are deliberately left
as written. See [docs/ARCHITECTURE.md](../ARCHITECTURE.md) for the module map
as it stands today.

ADRs from 0017 onward are written against the current API and are current
decisions, not history:

- [0017 — One authorization kernel; RBAC is authoring sugar over it](0017-one-authorization-kernel.md)
