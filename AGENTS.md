# AGENTS.md

`CLAUDE.md` is a symlink to this file. effect-auth is a library monorepo: authentication and authorization for [Effect](https://effect.website/) v4, as thirteen `@thomasfosterau/effect-auth*` packages under `packages/*`. Twelve are publishable; `effect-auth-alchemy` is `"private": true` until #250. It has no application, no deployment and no secrets.

Every package publishes `dist/`. Every package except the four framework bindings peers `effect` through `catalog:peers`; a binding peers only its framework. The archetype decides what a package may import:

| Archetype              | Packages                                        | Rule                                                                                                                                                                                                                                                                                                                                                                                                                                          |
| ---------------------- | ----------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **Core**               | `effect-auth` (`@thomasfosterau/effect-auth`)   | Depends on `effect` only. Flat root modules for the spine (sessions, users, the authorization kernel: `Policy`, `Condition`, `Entity`, `Authorizer`, `Rbac`, …) plus lowercase cluster directories (`email/`, `http/`, `oauth/`, `password/`, `plugins/`, `multifactor/`), each with a subpath export. `./ladder` (`src/Ladder.ts`) imports nothing, not even `effect`, because browser bundles load it; `ModuleGraph.test.ts` enforces this. |
| **Storage adapters**   | `sql`, `drizzle`, `alchemy`                     | Implement the core's store contracts (`SessionStore`, `UserStore`, `ApiKeyStore`, …) over a database. The database library is a **peer**, never bundled.                                                                                                                                                                                                                                                                                      |
| **Vendor adapters**    | `argon2`, `resend`, `twilio`, `saml`            | Implement one core seam (`PasswordHasher`, `EmailSender`, `SmsSender`, `SamlVerifier`) over one vendor. Plain `fetch` against the vendor's REST API rather than an SDK where possible; Workers-safe.                                                                                                                                                                                                                                          |
| **Client**             | `client` (`@thomasfosterau/effect-auth-client`) | The typed browser client over the HTTP contract plus the observable session store; `./testing` publishes the in-memory server fixture.                                                                                                                                                                                                                                                                                                        |
| **Framework bindings** | `react`, `svelte`, `solid`, `vue`               | Thin bindings over `client`. The framework is a peer.                                                                                                                                                                                                                                                                                                                                                                                         |

A new package picks an archetype, gets a `vite.config.ts` that declares its tasks through `packageTasks` ([vite.tasks.ts](vite.tasks.ts)), and gets a changeset.

## Common pitfalls

- **Never depend on legation**, in any package and in any dependency field, dev dependencies included. effect-auth may depend on effect-jsonapi. [docs/BOUNDARY.md](docs/BOUNDARY.md) holds the reason and the full rules.
- **Importing the core package root is meant not to pull the HTTP tier** (`http/`, and through it `effect/http-api` and effect-jsonapi) into a consumer's module graph. **Today it does:** the root barrel re-exports `Http` (`src/index.ts`), and the guard in `ModuleGraph.test.ts` is skipped until #205 lands. Don't add any other root-reachable import of `effect/http-api`.
- **Every external version lives in the catalog** in [pnpm-workspace.yaml](pnpm-workspace.yaml) (`catalogMode: strict` rejects anything else). After editing it, run `pnpm install` and commit `pnpm-lock.yaml`, or CI fails with `ERR_PNPM_LOCKFILE_CONFIG_MISMATCH`. `effect` is a singleton (`overrides`); its published floor lives in `catalogs.peers`.
- **`effect-auth-alchemy` is held private until #250** (alchemy beta.79 imports the removed `effect/unstable/*`). Its `build`, `check` and `test:unit` run; `AuthSchema.test.ts` needs the alchemy runtime, so it lives in `test:alchemy`, which runs in its own non-required CI job and is expected to fail until #250. Don't skip that test or move it into `test:unit`.

## Conventions

- **Optional properties are `?: T | undefined`.** `exactOptionalPropertyTypes` is on (`tsconfig.base.json`), so a bare `?: T` rejects a caller that forwards its own optional value.
- **Relative imports carry the `.ts` extension** (`rewriteRelativeImportExtensions`).
- **Tests import from `vite-plus/test`**, never `vitest`; lint (`vite-plus/prefer-vite-plus-imports`) rejects the direct import.
- **Services are `Context.Service` classes with a static `layer`**, and dependencies are resolved at layer construction so service methods carry `R = never`.
- **Errors follow [DESIGN.md](docs/DESIGN.md) D4:** domain errors are `Data.TaggedError`; HTTP-boundary errors in `http/HttpApiSchema.ts` are `Schema.TaggedError` classes with a status. HTTP is `effect/http-api`.
- **Secrets are compared with `constantTimeHashEqual` / `timingSafeEqualBytes`** (`src/TokenHash.ts`) and randomness comes from the `Crypto.Crypto` service (default `PlatformCrypto.layer`); direct `node:crypto` use stays corralled in `password/Password.ts`, `TokenHash.ts` and `Cipher.ts`.

## Commands

- `vp install` — dependencies, plus the Vite+ git hooks (pre-commit runs `vp staged`: format + lint on staged files). There is no pre-push hook.
- `vp check` — format + lint (Oxfmt + Oxlint). `vp run check` — the type gate: every package's `tsc` over sources and tests (`vue-tsc` / `svelte-check` where relevant) plus `vp test --typecheck`. They are different commands.
- `vp run -r test:unit` — every package's unit tests.
- `vp run build` — every package's `dist/`. Each package's `build`, `check` and `test:unit` first build the workspace packages it depends on (their `exports` point at the gitignored `dist/`), so a fresh checkout needs no manual build.
- `vp run check:dist` (network) — packs the built packages, installs them from the registry beside one exact `effect` (default the peer floor; `-- --effect catalog` for the version the workspace builds against) and imports every entry point. Run `vp run build` first.
- `vp run docs` — docgen for `packages/effect-auth`: writes the API reference and compiles and runs every JSDoc `@example`. It currently fails before reaching the examples (undocumented barrel re-exports), so it isn't a gate yet (#257).
- `pnpm changeset` — add a changeset.

## Verification

Before you report work as done, run the gates below in order and quote each command with its final pass/fail. If a gate can't run here, say which and why in the PR body; never imply it ran. This is CI's order ([ci.yml](.github/workflows/ci.yml), job `test`):

1. `vp check`
2. `vp run build`
3. `vp run check:dist`
4. `vp run check:dist -- --effect catalog`
5. `vp run check`
6. `vp run -r test:unit`
7. `pnpm audit --audit-level high` (network)

CI's second job, `alchemy`, runs `vp run --filter @thomasfosterau/effect-auth-alchemy test:alchemy`; it is not required and fails until #250. CI doesn't run `vp run docs` until #257 lands.

## Branches and pull requests

- Branch off `trunk` as `issue-<n>-<slug>`; PR against `trunk`; squash-merge. One issue per PR.
- Rebase onto `origin/trunk` before opening or updating a PR; never merge `trunk` into your branch (GitHub's Update-branch button merges).
- Once a branch has a pushed commit, open the PR without being asked, watch it to merge or close (CI failures, review comments), and keep the body current: what changed and why, which gates ran with their result, the changesets added.
- Every change to a published package's behaviour carries a changeset (`pnpm changeset`) naming each package it touches. Changes to doc comments that reach the emitted `.d.ts` (TSDoc) take a `patch` changeset; other docs-only changes (READMEs, guidance), CI and tooling need none. Never publish or version by hand: the Release workflow opens the version PR (`chore: version packages`) and the owner merges it. [PUBLISHING.md](PUBLISHING.md) has the pipeline.
- GitHub writes go to `thomasfosterau/effect-auth` only; pass `-R thomasfosterau/effect-auth` whenever the cwd might be another checkout. Use the `gh` CLI for GitHub operations, even when GitHub MCP tools are available.

## Work tracker

Issues are the backlog: when you find work you can't do now, file an issue rather than leaving a TODO; a TODO in code cites its issue (`TODO(#205)`). The issue is the spec — read its comments (`gh issue view <n> --comments`); later comments override the body, and its code claims need re-checking against current `trunk`. Record decisions and findings as issue comments. Stop-and-report is a valid outcome: on a blocker outside the issue's scope, comment the evidence on the issue and stop. Scope cut mid-PR becomes a linked issue before merge.

## Effect

Consult effect-solutions before writing Effect code (`vp exec effect-solutions list`, then `vp exec effect-solutions show <topic>…`); never guess at an Effect pattern. If it isn't available, read `node_modules/effect/dist/*.d.ts`, or the source in `node_modules/effect/src`. The pinned version is the `effect` entry in `pnpm-workspace.yaml`'s catalog.

## Agent sessions

The SessionStart hook ([.claude/hooks/session-start.sh](.claude/hooks/session-start.sh), also the devcontainer's `postCreateCommand`) installs dependencies against the lockfile and links `vp` and `tsx` onto PATH for non-interactive shells. It hydrates no secrets; none are needed. A PostToolUse hook (`.claude/settings.json`) runs `vp fmt --write` on every file you edit, so edits get reformatted after you write them. `vp run check:dist` and `pnpm audit` need registry access.

## Documentation surfaces

- Domain vocabulary: [docs/CONTEXT.md](docs/CONTEXT.md) · API conventions: [docs/DESIGN.md](docs/DESIGN.md) · module map and security model: [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) · decisions: [docs/adr/](docs/adr/README.md) (read [ADR-0017](docs/adr/0017-batteries-included-auth-framework.md) and [ADR-0018](docs/adr/0018-one-authorization-kernel.md) first) · library boundary: [docs/BOUNDARY.md](docs/BOUNDARY.md).
- Each package `README.md` is the API reference consumers read on npm; the root README is a landing page.
- [CONTRIBUTING.md](CONTRIBUTING.md) holds human procedures; [PUBLISHING.md](PUBLISHING.md) the release pipeline and owner setup; [SECURITY.md](SECURITY.md) vulnerability reporting.
- A new settled design decision gets the next ADR number and a row in the ADR index; other decisions and findings go in issue comments.
