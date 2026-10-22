# AGENTS.md

`CLAUDE.md` is a symlink to this file. effect-auth is a library monorepo: authentication and authorization for [Effect](https://effect.website/) v4, as thirteen publishable `@thomasfosterau/effect-auth*` packages under `packages/*`. It has no application, no deployment and no secrets.

Every package publishes `dist/`. Every package except the four framework bindings and `alchemy` peers `effect` through `catalog:peers`; `alchemy` peers it through `catalog:alchemy-peers` (floor `4.0.0`, because its `alchemy` peer requires `effect ^4.0.0`); a binding peers only its framework. The archetype decides what a package may import:

| Archetype              | Packages                                        | Rule                                                                                                                                                                                                                                                                                                                                                                                                                                          |
| ---------------------- | ----------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **Core**               | `effect-auth` (`@thomasfosterau/effect-auth`)   | Depends on `effect` only. Flat root modules for the spine (sessions, users, the authorization kernel: `Policy`, `Condition`, `Entity`, `Authorizer`, `Rbac`, …) plus lowercase cluster directories (`email/`, `http/`, `oauth/`, `password/`, `plugins/`, `multifactor/`), each with a subpath export. `./ladder` (`src/Ladder.ts`) imports nothing, not even `effect`, because browser bundles load it; `ModuleGraph.test.ts` enforces this. |
| **Storage adapters**   | `sql`, `drizzle`, `alchemy`                     | Implement the core's store contracts (`SessionStore`, `UserStore`, `ApiKeyStore`, …) over a database. The database library is a **peer**, never bundled.                                                                                                                                                                                                                                                                                      |
| **Vendor adapters**    | `argon2`, `resend`, `twilio`, `saml`            | Implement one core seam (`PasswordHasher`, `EmailSender`, `SmsSender`, `SamlVerifier`) over one vendor. Plain `fetch` against the vendor's REST API rather than an SDK where possible; Workers-safe.                                                                                                                                                                                                                                          |
| **Client**             | `client` (`@thomasfosterau/effect-auth-client`) | The typed browser client over the HTTP contract plus the observable session store; `./testing` publishes the in-memory server fixture.                                                                                                                                                                                                                                                                                                        |
| **Framework bindings** | `react`, `svelte`, `solid`, `vue`               | Thin bindings over `client`. The framework is a peer.                                                                                                                                                                                                                                                                                                                                                                                         |

A new package picks an archetype, gets a `vite.config.ts` that declares its tasks through `packageTasks` ([vite.tasks.ts](vite.tasks.ts)), its own `CLAUDE.md` (boundary, invariants, terms), a row in the root `README.md`, its entry points and a zone (or a place in its archetype's zone) in [.fallowrc.json](.fallowrc.json), its `#build` edge in the root `test:coverage` task (`vite.config.ts`), and a changeset.

## Common pitfalls

- **Never depend on legation**, in any package and in any dependency field, dev dependencies included. effect-auth may depend on effect-jsonapi. [docs/BOUNDARY.md](docs/BOUNDARY.md) holds the reason and the full rules.
- **Importing the core package root is meant not to pull the HTTP tier** (`http/`, and through it `effect/http-api` and effect-jsonapi) into a consumer's module graph. **Today it does:** the root barrel re-exports `Http` (`src/index.ts`), and the guard in `ModuleGraph.test.ts` is skipped until #205 lands. Don't add any other root-reachable import of `effect/http-api`.
- **Every external version lives in the catalog** in [pnpm-workspace.yaml](pnpm-workspace.yaml) (`catalogMode: strict` rejects anything else). After editing it, run `pnpm install` and commit `pnpm-lock.yaml`, or CI fails with `ERR_PNPM_LOCKFILE_CONFIG_MISMATCH`. `effect` is a singleton (`overrides`); its published floor lives in `catalogs.peers`, and effect-auth-alchemy's higher one in `catalogs.alchemy-peers`. Dependabot ([dependabot.yml](.github/dependabot.yml)) groups each move-together set (the `toolchain` set, `effect` + `@effect/*`, each framework family) into one PR; the advisory floors under `overrides` (`brace-expansion@5`, `js-yaml@3`, …) are not dependencies it can bump, so raise or drop them by hand when `pnpm audit` or their dependents move.
- **`effect-auth-alchemy`'s `AuthSchema.test.ts` is its own task.** It is the one suite that loads the alchemy runtime, so it lives in `test:alchemy`, run by CI's separate `alchemy` job ("Alchemy runtime"), not in `test:unit`. Don't skip it. alchemy 2.0.0-beta.80 is the first release that imports only `effect/*` paths (beta.79 and earlier import the removed `effect/unstable/*`, #250), so `catalogs.peers` floors `alchemy` there.
- **TypeScript is split 6/7.** `typescript` in the catalog is an alias for TS6 (the JS compiler API, bin `tsc6`) because `vue-tsc`, `svelte-check`, `@effect/docgen` and the editor language service all `require("typescript")` and TS7 ships no JS API. `@typescript/native` is TS7 (bin `tsc`), which every package's `build` and `check` script runs; the root `prepare` script patches it, and `vite-plus`'s oxlint, with `@effect/tsgo` (`effect-tsgo patch --typescript --oxlint`; the patched oxlint carries the `effecttsgo` plugin the lint config extends, and stock oxlint rejects the config). `@effect/tsgo`, `@typescript/native` and `vite-plus` move as a set of three, kept inside the `components` table in `node_modules/@effect/tsgo/dist/effect-tsgo.cjs`: that table lists the TypeScript and oxlint versions each `@effect/tsgo` release supports, and `vite-plus` pins the oxlint. Read it before bumping any of them, since the patch hard-errors at install on a TypeScript it has no artifact for. Never bump `typescript` itself to 7 (Dependabot proposes exactly that, and it breaks every JS-API consumer).
- **`@effect-diagnostics` directives are read by the patched `tsc`, and only in the unprefixed form:** the rule name, then the severity, as in `// @effect-diagnostics-next-line multipleEffectProvide:off` (`packages/alchemy/src/AuthSchema.test.ts`). The `effect/<rule>:off` form that `@effect/language-service`'s README shows is silently ignored by the `@effect/tsgo`-patched TS7 `tsc` (checked against `@effect/tsgo` 0.46.1).
- **`vue-tsc` type-checks `packages/vue` without the Effect plugin.** It runs on the TS6 JS API, not the tsgo-patched `tsc`, so no Effect diagnostics (or `@effect-diagnostics` directives) apply there. That is fine while `packages/vue/src` imports nothing from `effect`; check the first `effect` import there deliberately.

## Conventions

- **Optional properties are `?: T | undefined`.** `exactOptionalPropertyTypes` is on (`tsconfig.base.json`), so a bare `?: T` rejects a caller that forwards its own optional value.
- **Relative imports carry the `.ts` extension** (`rewriteRelativeImportExtensions`).
- **Tests import from `vite-plus/test`**, never `vitest`; lint (`vite-plus/prefer-vite-plus-imports`) rejects the direct import.
- **Lint extends `@effect/tsgo/oxlint-presets`' `recommended` and `@mpsuesser/oxlint-plugin-effect`'s `recommended`** in the root `vite.config.ts`. A rule is turned `off` only with a comment giving the convention it contradicts; the overrides scope the platform-service rules off for Node-only code (tests, `testing/`, scripts, configs) and the `effect`-module rules off for code that imports no `effect` (the bindings, `./ladder`). The rules under "ported-code allowances" sit at `warn` for code that predates them (#ALLOWANCE); a new site is a defect, and a rule whose count reaches zero has its line deleted so it is back at `error`. Fix findings by changing the code, never with a disable comment.
- **Services are `Context.Service` classes with a static `layer`**, and dependencies are resolved at layer construction so service methods carry `R = never`.
- **Errors follow [DESIGN.md](docs/DESIGN.md) D4:** domain errors are `Data.TaggedError`; HTTP-boundary errors in `http/HttpApiSchema.ts` are `Schema.TaggedError` classes with a status. HTTP is `effect/http-api`.
- **Secrets are compared with `constantTimeHashEqual` / `timingSafeEqualBytes`** (`src/TokenHash.ts`) and randomness comes from the `Crypto.Crypto` service (default `PlatformCrypto.layer`); direct `node:crypto` use stays corralled in `password/Password.ts`, `TokenHash.ts` and `Cipher.ts`.

## Commands

- `vp install` — dependencies, plus the Vite+ git hooks (pre-commit runs `vp staged`: format + lint on staged files). There is no pre-push hook.
- `vp check` — format + lint (Oxfmt + Oxlint). `vp run check` — the type gate: every package's `tsc` over sources and tests (`vue-tsc` / `svelte-check` where relevant), plus `vp test --typecheck`, plus `vp run check:scripts` over `scripts/`. They are different commands.
- `vp run -r test:unit` — every package's unit tests.
- `vp run build` — every package's `dist/`. Each package's `build`, `check` and `test:unit` first build the workspace packages it depends on (their `exports` point at the gitignored `dist/`), so a fresh checkout needs no manual build.
- `vp run check:dist` (network) — packs the built packages, installs them from the registry beside an exact `effect` and imports every entry point. By default each package gets the floor of its own packed `effect` peer range (`catalogs.alchemy-peers` floors effect-auth-alchemy above the rest, so it installs in its own project); `-- --effect catalog` installs all of them at the version the workspace builds against; `-- --effect <version>` skips each package whose range excludes that version. Each run fails if the installed `effect` misses the range one of our packages or an installed peer (such as `alchemy`) declares. Run `vp run build` first.
- `vp run check:scripts` — type-checks `scripts/` (`check-dist.ts`) against the root `tsconfig.scripts.json`. The root `check` script runs it after the packages' checks, so `vp run check` (and CI's Type check step) covers `scripts/`; there is no separate gate for it. Run it alone only to iterate on `scripts/`.
- `vp run docs` — docgen for `packages/effect-auth`: writes the API reference to `packages/effect-auth/docs/` (gitignored), type-checks every JSDoc `@example`, then runs them (`runExamples` is on in `docgen.json`). The examples run in one `tsx` process, so each must run to completion with no network, no secrets and no real database: stores are in-memory, config comes from inline values, and an example fails by throwing or failing an `assert`. They import the package by its own name, so run `vp run build` first. Examples never use `declare` stubs to avoid running. An example that needs persistence stores builds its layers over `Testing.memoryStores` (`@thomasfosterau/effect-auth/testing`); only `RateLimitPersistence.ts`'s Redis example is composed and not run, since its Lua scripts need a real Redis.
- `vp run test:coverage` — every package's unit suite (alchemy's runtime suite aside) under one Istanbul map at `coverage/coverage-final.json`, which `fallow audit` reads for exact per-function CRAP scores. Without the map fallow scores every function as uncovered, and any function with cyclomatic complexity ≥ 5 fails the gate on its own.
- `fallow dead-code` / `fallow health` / `fallow audit --base origin/trunk` — dead code, complexity and the changed-files gate, configured in [.fallowrc.json](.fallowrc.json) (zones per archetype: `bindings` may import only `client`; `client` and the adapters only `core`; `core` nothing but `ladder`; `ladder` nothing). `duplicate-exports` is off because same-named members of namespaced modules (`make`, `layer`) are the convention. `duplicates.ignoredClones` lists reviewed clone groups that span packages which may not import each other (the bindings' form internals, the sql and drizzle stores, resend and twilio's response reads, the two PGlite templates); a change to one of them produces a new fingerprint and reports it again. Public class members fallow cannot see a caller for stay `warn`.
- `pnpm changeset` — add a changeset.

## Verification

Before you report work as done, run the gates below in order and quote each command with its final pass/fail. If a gate can't run here, say which and why in the PR body; never imply it ran. Steps 1–8 are CI's order ([ci.yml](.github/workflows/ci.yml), job `test`):

1. `vp check`
2. `vp run build`
3. `vp run docs`
4. `vp run check:dist`
5. `vp run check:dist -- --effect catalog`
6. `vp run check`
7. `vp run -r test:unit`
8. `pnpm audit --audit-level high` (network)
9. `vp run test:coverage`, then `fallow audit --format json --quiet --explain --gate-marker agent --base origin/trunk` (the fallow gate below; not a CI step). The PreToolUse fallow gate audits against `coverage/coverage-final.json` and never refreshes it, so run `test:coverage` first.

CI's second job, `alchemy` ("Alchemy runtime"), runs `vp run --filter @thomasfosterau/effect-auth-alchemy test:alchemy`.

## Branches and pull requests

- Branch off `trunk` as `issue-<n>-<slug>`; PR against `trunk`; squash-merge. One issue per PR.
- Rebase onto `origin/trunk` before opening or updating a PR; never merge `trunk` into your branch (GitHub's Update-branch button merges).
- Once a branch has a pushed commit, open the PR without being asked, watch it to merge or close (CI failures, review comments), and keep the body current: what changed and why, which gates ran with their result, the changesets added.
- Every change to a published package's behaviour carries a changeset (`pnpm changeset`) naming each package it touches. Changes to doc comments that reach the emitted `.d.ts` (TSDoc) take a `patch` changeset; other docs-only changes (READMEs, guidance), CI and tooling need none. Never publish or version by hand: the Release workflow opens the version PR (`chore: version packages`) and the owner merges it. [PUBLISHING.md](PUBLISHING.md) has the pipeline.
- GitHub writes go to `thomasfosterau/effect-auth` only; pass `-R thomasfosterau/effect-auth` whenever the cwd might be another checkout. Use the `gh` CLI for GitHub operations, even when GitHub MCP tools are available.

## Work tracker

Issues are the backlog: when you find work you can't do now, file an issue rather than leaving a TODO; a TODO in code cites its issue (`TODO(#205)`). The issue is the spec — read its comments (`gh issue view <n> --comments`); later comments override the body, and its code claims need re-checking against current `trunk`. Record decisions and findings as issue comments. Stop-and-report is a valid outcome: on a blocker outside the issue's scope, comment the evidence on the issue and stop. Scope cut mid-PR becomes a linked issue before merge.

## Effect

Read the installed package before writing Effect code: `node_modules/effect/AGENTS.md` and `node_modules/effect/ai-docs/` (the pinned version ships both), the declarations in `node_modules/effect/dist/*.d.ts` and the source in `node_modules/effect/src`. Never guess at an Effect API: v4 renamed much of v3. The pinned version is the `effect` entry in `pnpm-workspace.yaml`'s catalog; the published floor is `catalogs.peers.effect`.

## Agent sessions

The SessionStart hook ([.claude/hooks/session-start.sh](.claude/hooks/session-start.sh), also the devcontainer's `postCreateCommand`) installs dependencies against the lockfile and puts `vp` (a re-exec shim that prefers the nearest worktree's `node_modules`), `fallow` and `tsx` on PATH for non-interactive shells. It hydrates no secrets; none are needed. A PreToolUse hook ([.claude/hooks/fallow-gate.sh](.claude/hooks/fallow-gate.sh)) blocks `git commit` / `git push` when `fallow audit --base origin/trunk` fails; it reads the coverage map on disk, so run `vp run test:coverage` first. A PostToolUse hook (`.claude/settings.json`) runs `vp fmt --write` on every file you edit, so edits get reformatted after you write them. `vp run check:dist` and `pnpm audit` need registry access.

## Documentation surfaces

- Domain vocabulary: [docs/CONTEXT.md](docs/CONTEXT.md) · API conventions: [docs/DESIGN.md](docs/DESIGN.md) · module map and security model: [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) · decisions: [docs/adr/](docs/adr/README.md) (read [ADR-0017](docs/adr/0017-batteries-included-auth-framework.md) and [ADR-0018](docs/adr/0018-one-authorization-kernel.md) first) · library boundary: [docs/BOUNDARY.md](docs/BOUNDARY.md).
- Each package `README.md` is the API reference consumers read on npm (links in it are absolute, since npm renders it without the repo); each package `CLAUDE.md` carries its boundary, invariants and terms; the root README is a landing page.
- [CONTRIBUTING.md](CONTRIBUTING.md) holds human procedures; [PUBLISHING.md](PUBLISHING.md) the release pipeline and owner setup; [SECURITY.md](SECURITY.md) vulnerability reporting.
- A new settled design decision gets the next ADR number and a row in the ADR index; other decisions and findings go in issue comments.

---

## Fallow local gate

Before any `git commit` or `git push`, run `fallow audit --format json --quiet --explain --gate-marker agent --base origin/trunk`. If the verdict is `fail`, fix the reported findings before retrying. Treat JSON runtime errors like `{ "error": true, ... }` as non-blocking. Audit defaults to `gate=new-only`: only findings introduced by the current changeset affect the verdict.

## Fallow task map

| When the agent is about to...                                     | Run                                          |
| ----------------------------------------------------------------- | -------------------------------------------- |
| delete an "unused" export or file                                 | `fallow dead-code --trace <file>:<export>`   |
| delete an "unused" dependency                                     | `fallow dead-code --trace-dependency <name>` |
| commit or open a PR                                               | `fallow audit --base origin/trunk`           |
| check which architecture rules apply to a file before changing it | `fallow guard <files>`                       |
| understand a finding                                              | `fallow explain <issue-type>`                |
