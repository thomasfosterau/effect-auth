# AGENTS.md

Read [README.md](README.md) and [docs/CONTRIBUTING.md](docs/CONTRIBUTING.md) first. Each package's `AGENTS.md` holds its boundary and invariants; read it before changing that package.

## Process

- You may open PRs in this repository; follow the workflow in docs/CONTRIBUTING.md and keep the PR body current (what changed, gates run with results, changesets).
- Out-of-scope work you notice: file an issue and move on.
- Use the GitHub MCP tools or `gh`, whichever is available. Write only to `thomasfosterau/effect-auth`.
- Never version or publish by hand: the Release workflow packs in one job, publishes the tarballs in another and tags in a third ([PUBLISHING.md](docs/PUBLISHING.md)). `vp run release:pack` publishes nothing and is safe.
- Use Effect v4's own modules rather than re-inventing them (exceptions in docs/CONTRIBUTING.md). Non-idiomatic code you find: fix it if trivial, otherwise file an issue listing the sites and the replacement.

## Pitfalls

- **Never depend on legation**, in any dependency field ([BOUNDARY.md](docs/BOUNDARY.md)). effect-jsonapi is fine.
- **The core's root never reaches `http/`, `client/`, `sql/` or `saml/`**, nor their optional peers (effect-jsonapi, `@node-saml/node-saml`); `./ladder` imports only `effect/Option`. `ModuleGraph.test.ts` enforces both. Code needing only `effect` is a core subpath, not a new package ([ADR-0022](docs/adr/0022-package-boundaries.md)).
- **Adapters depend on the core as `workspace:^`**, never `workspace:*` (an exact pin leaves an adapter on its own nested core).
- **TypeScript is split 6/7.** `typescript` is a TS6 alias for JS-API consumers; never bump it to 7. `@typescript/native` (TS7), `@effect/tsgo` and `vite-plus` move together, or `vp install` fails.
- **`@effect-diagnostics` directives** work only unprefixed (`// @effect-diagnostics-next-line multipleEffectProvide:off`); the `effect/<rule>` form is silently ignored.
- **The alchemy runtime suites** (`AuthSchema.test.ts`, alchemy-postgres's `Postgres.test.ts`) run in `test:alchemy`, not `test:unit`. The Postgres cases skip without `DATABASE_URL`; say so when you report gates.
- **`check:dist` proves every published floor** (`scripts/check-dist.ts`). It packs each package (checking `repository.directory`, which npm resolves README links against), installs it with pnpm beside the lowest `effect` and third-party peer versions its packed ranges admit (one scratch project per floor; `autoInstallPeers` off, so it re-checks every installed range itself), imports every entry, and runs the core's behaviour phase (env layers, `protectedField`) and drizzle's query smoke and strict consumer type-check, on the floor and on `drizzleApplicationsPin`. Importing alone misses APIs that moved inside the range, so a new call near a floor joins the behaviour phase. A floor npm never published fails by name.

## Fallow

The pre-commit hook runs `vp run fallow:audit` (a full coverage run, then the audit); fix a `fail` verdict rather than skipping the hook. Only findings your change introduces count. Before deleting "unused" code, trace it: `vp exec fallow dead-code --trace <file>:<export>`.

The `fallow` agent skill is linked into `.claude/skills/` from the installed package after `vp install`.
