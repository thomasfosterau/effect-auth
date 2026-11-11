# Contributing to effect-auth

effect-auth is a pnpm workspace of nine `@thomasfosterau/effect-auth*` packages under `packages/*`; the core library is `packages/effect-auth`. This file holds setup, the commands and the branch / PR / changeset rules, for humans and agents alike. [AGENTS.md](AGENTS.md) holds the conventions, the pitfalls and the gate list, and each package's `AGENTS.md` its boundary, invariants and vocabulary; this file doesn't restate them.

## Setup

You need Node.js `^20.19.0 || ^22.18.0 || >=24.11.0` (`engines` in the root `package.json`) and pnpm 11 (the `packageManager` field pins the exact version, currently `pnpm@11.11.0`; Corepack resolves it).

```bash
git clone https://github.com/thomasfosterau/effect-auth.git
cd effect-auth
vp install   # or: pnpm install
```

Either command installs against the lockfile and runs the root `prepare` script, which installs the Vite+ git hooks and patches the TypeScript 7 `tsc` (and oxlint) with `@effect/tsgo` so the Effect diagnostics run in every type check. The pre-commit hook runs `vp staged`: format (with fixes) and lint (without fixes, so a type-aware autofix never lands unverified) on the staged files. There is no pre-push hook.

You don't need to build anything first: each package's `build`, `check` and `test:unit` tasks build the workspace packages they depend on.

Open in a Codespace or Dev Container: `.devcontainer/` provisions it with the same hook as agent sessions. The `Dev Container` workflow (`.github/workflows/devcontainer.yml`) builds it in CI whenever its inputs change; to try a change locally, `pnpm dlx @devcontainers/cli@0.89.0 up --workspace-folder .` (needs Docker).

For Effect APIs, read what the pinned `effect` ships: `node_modules/effect/AGENTS.md`, `node_modules/effect/ai-docs/`, and the declarations in `node_modules/effect/dist/*.d.ts`.

## Making a change

1. Find or file the issue, and branch off `trunk` as `issue-<n>-<slug>` ([Branches and pull requests](#branches-and-pull-requests)).
2. Follow the module conventions in [docs/DESIGN.md](docs/DESIGN.md): a service class with a static `layer`, store interfaces whose lookups return `null` on a miss, tagged errors.
   - Shared types go in `src/Types.ts`; errors raised by two or more modules go in `src/Errors.ts`, others stay in their module.
   - A new module goes in `src/<Feature>.ts`, or `src/<cluster>/<Feature>.ts` inside an existing cluster (`email/`, `http/`, `oauth/`, `password/`, `plugins/`, `multifactor/`), and is exported from that cluster's `index.ts` or from `src/index.ts`.
3. Put tests next to the source (`Password.test.ts` beside `Password.ts`). Tests use Vitest through `vite-plus/test`; lint rejects a direct `vitest` import.

   ```typescript
   import { describe, expect, it } from "vite-plus/test";
   ```

   Cover the error cases and the security properties (timing, entropy, expiry, replay), not only the happy path. Storage adapters test against real engines in-process: `packages/drizzle`'s PostgreSQL suites run on [PGlite](https://github.com/electric-sql/pglite) (so `jsonb`, `timestamptz` and unique-index violations behave as in production) and its SQLite suite on `better-sqlite3`; `Requests.test.ts` counts the SQL a program emits through drizzle's `logger` hook to prove the batching claims, and `MySqlSchema.test.ts` pins the MySQL SQL through the proxy driver.

4. Document the change in the affected package's `README.md` (the API reference npm shows; use absolute `https://github.com/thomasfosterau/effect-auth/blob/trunk/…` links there, since npm renders it without the repository) and its `AGENTS.md` when an invariant changes; update [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) if the module map changes.
5. Add a changeset with `pnpm changeset` when the change affects a published package, naming every package it touches ([Branches and pull requests](#branches-and-pull-requests) says which changes need one). Never version or publish by hand: the Release workflow opens the `chore: version packages` PR ([PUBLISHING.md](PUBLISHING.md)).

### Security-sensitive code

- Compare secrets in constant time with `constantTimeHashEqual` / `timingSafeEqualBytes` (`src/TokenHash.ts`).
- Draw randomness from the `SecureRandom.SecureRandom` service (`effect/crypto`; default `PlatformCrypto.layer`), never `Math.random`.
- Store bearer tokens as SHA-256 digests (`hashToken`), never raw.
- Never log passwords, tokens, API keys or secrets.

[docs/ARCHITECTURE.md → Security Considerations](docs/ARCHITECTURE.md#security-considerations) describes the model these rules protect.

## Commands

- `vp install` — dependencies, plus the Vite+ git hooks (pre-commit runs `vp staged`: format + lint on staged files). There is no pre-push hook.
- `vp check` — format + lint (Oxfmt + Oxlint). Lint is type-aware through oxlint-tsgolint, which resolves sibling packages through their built `dist/`, so run `vp run build` first (`typeCheck` stays off: `vp run check` is the type gate). `vp run check` — the type gate: every package's `tsc` over sources and tests (`svelte-check` for `packages/svelte`), plus `vp test --typecheck`, plus `vp run check:scripts` over `scripts/`. They are different commands.
- `vp run -r test:unit` — every package's unit tests.
- `vp run build` — every package's `dist/`. Each package's `build`, `check` and `test:unit` first build the workspace packages it depends on (their `exports` point at the gitignored `dist/`), so a fresh checkout needs no manual build.
- `vp run check:dist` (network) — packs the built packages, installs them from the registry beside an exact `effect` and imports every entry point. By default each package gets the floor of its own packed `effect` peer range (`catalogs.alchemy-peers` floors the Alchemy packages apart from the rest, so they install in their own project); `-- --effect catalog` installs all of them at the version the workspace builds against; `-- --effect <version>` skips each package whose range excludes that version. Each run fails if the installed `effect` misses the range one of our packages or an installed peer (such as `alchemy`) declares. Run `vp run build` first.
- `vp run check:scripts` — type-checks `scripts/` (`check-dist.ts`) against the root `tsconfig.scripts.json`. The root `check` script runs it after the packages' checks, so `vp run check` (and CI's Type check step) covers `scripts/`; there is no separate gate for it. Run it alone only to iterate on `scripts/`.
- `vp run docs` — docgen for `packages/effect-auth`: writes the API reference to `packages/effect-auth/docs/` (gitignored), type-checks every JSDoc `@example`, then runs them (`runExamples` is on in `docgen.json`). The examples run in one `tsx` process, so each must run to completion with no network, no secrets and no real database: stores are in-memory, config comes from inline values, and an example fails by throwing or failing an `assert`. They import the package by its own name, so run `vp run build` first. Examples never use `declare` stubs to avoid running. An example that needs persistence stores builds its layers over `Testing.memoryStores` (`@thomasfosterau/effect-auth/testing`); only `RateLimitPersistence.ts`'s Redis example is composed and not run, since its Lua scripts need a real Redis.
- `vp run test:coverage` — every package's unit suite (the Alchemy runtime suites aside) under one Istanbul map at `coverage/coverage-final.json`, which `fallow audit` reads for exact per-function CRAP scores. Without the map fallow scores every function as uncovered, and any function with cyclomatic complexity ≥ 5 fails the gate on its own.
- `vp exec fallow dead-code` / `vp exec fallow health` / `vp exec fallow audit --base origin/trunk` — dead code, complexity and the changed-files gate, configured in [.fallowrc.json](.fallowrc.json) (zones per archetype: the bindings and adapters may import only `core` and `ladder`, the Svelte binding in practice only `/client`; `core` nothing but `ladder`; `ladder` nothing). `duplicate-exports` is off because same-named members of namespaced modules (`make`, `layer`) are the convention. `duplicates.ignoredClones` lists reviewed clone groups that span packages which may not import each other (the core's `/sql` and drizzle stores, resend and twilio's response reads, the two PGlite templates, the two Alchemy `AuthSchema` providers and their engine harnesses); a change to one of them produces a new fingerprint and reports it again. Public class members fallow cannot see a caller for stay `warn`.
- `pnpm changeset` — add a changeset.

## Running one check

The full gate list is in [AGENTS.md → Verification](AGENTS.md#verification). While iterating, run the piece you need:

| What                                   | Command                                                                   |
| -------------------------------------- | ------------------------------------------------------------------------- |
| Format and lint everything             | `vp check` (type-aware; build first; `--fix` applies fixes)               |
| Lint one file                          | `vp lint <file>`                                                          |
| Format files                           | `vp fmt <files> --write`                                                  |
| One package's unit tests               | `vp run --filter <pkg> test:unit`                                         |
| One package's type check               | `vp run --filter <pkg> check`                                             |
| One test file (from the package's dir) | `vp test run <file>`                                                      |
| The alchemy runtime suites             | `vp run --filter './packages/alchemy-*' test:alchemy`                     |
| Coverage map for fallow                | `vp run test:coverage` (writes `coverage/coverage-final.json`)            |
| Dead code, unused exports, boundaries  | `vp exec fallow dead-code`                                                |
| The changed-files gate                 | `vp exec fallow audit --base origin/trunk` (after `vp run test:coverage`) |
| API docs and their runnable examples   | `vp run build && vp run docs`                                             |

`<pkg>` is the package name, for example `@thomasfosterau/effect-auth-drizzle`. `vp check` (format and lint) and `vp run check` (the type gate) are different commands.

## Branches and pull requests

- Branch off `trunk` as `issue-<n>-<slug>`; PR against `trunk`; squash-merge. One issue per PR.
- Rebase onto `origin/trunk` before opening or updating a PR; never merge `trunk` into your branch (GitHub's Update-branch button merges).
- Every change to a published package's behaviour carries a changeset (`pnpm changeset`) naming each package it touches. Changes to doc comments that reach the emitted `.d.ts` (TSDoc) take a `patch` changeset; other docs-only changes (READMEs, guidance), CI and tooling need none. Never publish or version by hand: the Release workflow opens the version PR (`chore: version packages`) and the owner merges it. [PUBLISHING.md](PUBLISHING.md) has the pipeline.

## Before you open a pull request

Run the gates in [AGENTS.md → Verification](AGENTS.md#verification), in that order, and record each result in the PR body; CI's `test` job runs the same list and its `alchemy` job runs the alchemy runtime suites. The PR template ([.github/pull_request_template.md](.github/pull_request_template.md)) asks for the rest.

## Reporting a vulnerability

Don't open a public issue; follow [SECURITY.md](SECURITY.md).

## License

By contributing, you agree that your contributions are licensed under the [MIT License](LICENSE.md).
