---
"@thomasfosterau/effect-auth": patch
"@thomasfosterau/effect-auth-sql": patch
"@thomasfosterau/effect-auth-drizzle": patch
"@thomasfosterau/effect-auth-client": patch
---

Every exported symbol has a doc-comment summary that shows in editor hovers: the core's service classes (with the stores each one requires), configs and results, the `Condition` and `Policy` scope constructors, the `Observability` record helpers, the HTTP list views and error schemas, the SQL stores and their layers, drizzle's row types and every `databaseLayer` overload, and `AuthClientOptions`. `hashToken` carries its own doc comment, and the client module overview opens with its summary rather than a tag line.

Doc comments on `SessionResolution.resolveFailOpen` and `resolveAtEdgeFailOpen` (`http/RemoteSession.ts`) point at `docs/ARCHITECTURE.md` for the fail-open precondition.
